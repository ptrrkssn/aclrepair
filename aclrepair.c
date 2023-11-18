/*
** aclrepair.c
**
 * Copyright (c) 2023, Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#define _ACL_PRIVATE 1
#include <sys/acl.h>

char *version = "0.2";

int f_update = 1;
int f_verbose = 0;
int f_user = 0;
int f_group = 0;
int f_everyone = 0;
int f_propagate = 0;
int f_cleanup = 0;     /* Strip ACL of stale (numeric) user & group entries */
int f_sort = 0;
int f_merge = 0;
int f_recurse = 0;

uid_t ouid = -1;
uid_t nuid = -1;

gid_t ogid = -1;
gid_t ngid = -1;


acl_t saved_dir_acl = NULL;
acl_t saved_file_acl = NULL;

char *argv0 = "aclrepair";

int n_chuid = 0;
int n_chgrp = 0;
int n_chacl = 0;
int n_file = 0;
int n_warn = 0;



/* &nap->ats_acl.acl_entry[0], nap->ats_acl.acl_cnt */
int
acl_merge(acl_t a) {
    int i, j, k;


    for (i = 0; i < a->ats_acl.acl_cnt; i++) {
	acl_entry_t ea;
	acl_tag_t ta;
	acl_permset_t pa;
	acl_flagset_t fa;
	acl_entry_type_t eta;
	uid_t *uap;
	gid_t *gap;
	
	ea = &a->ats_acl.acl_entry[i];
	acl_get_tag_type(ea, &ta);
	switch (ta) {
	case ACL_USER:
	    uap = (uid_t *) acl_get_qualifier(ea);
	    break;
	case ACL_GROUP:
	    gap = (gid_t *) acl_get_qualifier(ea);
	    break;
	}
	acl_get_flagset_np(ea, &fa);
	acl_get_entry_type_np(ea, &eta);
	acl_get_permset(ea, &pa);

	/* Look for duplicate entries */
	for (j = i+1; j < a->ats_acl.acl_cnt; j++) {
	    acl_entry_t eb;
	    acl_entry_type_t etb;
	    acl_tag_t tb;
	    acl_permset_t pb;
	    acl_flagset_t fb;
	    uid_t *ubp;
	    gid_t *gbp;
	    
	    eb = &a->ats_acl.acl_entry[j];
	    acl_get_tag_type(eb, &tb);
	    if (tb != ta)
		continue;
	    
	    switch (tb) {
	    case ACL_USER:
		ubp = (uid_t *) acl_get_qualifier(eb);
		if (*uap != *ubp)
		    continue;
		break;
	    case ACL_GROUP:
		gbp = (gid_t *) acl_get_qualifier(eb);
		if (*gap != *gbp)
		    continue;
		break;
	    }
	    acl_get_entry_type_np(eb, &etb);
	    if (etb != eta)
		continue;

	    acl_get_flagset_np(eb, &fb);
	    if (*fa != *fb)
		continue;
	    
	    /* Same entry tag type, flags & type (allow/deny) */
	    acl_get_permset(eb, &pb);
	    *pa |= *pb;

	    for (k = j; k < a->ats_acl.acl_cnt-1; k++)
		a->ats_acl.acl_entry[k] = a->ats_acl.acl_entry[k+1];
	    a->ats_acl.acl_cnt--;
	}
    }

    return a->ats_acl.acl_cnt;
}


/* Compare two ACL Entries */
static int
acl_entry_compare(const void *va,
		  const void *vb) {
  acl_entry_t a = (acl_entry_t) va;
  acl_entry_t b = (acl_entry_t) vb;
  acl_entry_type_t aet_a, aet_b;
  acl_tag_t ta, tb;
  acl_flagset_t afs, bfs;
  int v;
  int inherited_a, inherited_b;
  int inherit_only_a, inherit_only_b;
  uid_t *qa, *qb;
  

  afs = bfs = NULL;
  acl_get_flagset_np(a, &afs);
  acl_get_flagset_np(b, &bfs);
  
  inherited_a = acl_get_flag_np(afs, ACL_ENTRY_INHERITED);
  inherited_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERITED);

  /* Explicit entries goes before inherited ones */
  v = inherited_a-inherited_b;
  if (v)
    return v;

  
  inherit_only_a = acl_get_flag_np(afs, ACL_ENTRY_INHERIT_ONLY);
  inherit_only_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERIT_ONLY);

  /* Ignore this entry if the 'inherit_only' flag is set on one of them */
  if (inherit_only_a || inherit_only_b)
    return 0;

  
  /* order: owner@ - user - group@ - group - everyone@ */
  ta = tb = 0;
  
  if (acl_get_tag_type(a, &ta) < 0)
    return -1;
  
  if (acl_get_tag_type(b, &tb) < 0)
    return 1;

  v = ta-tb;
  if (v)
    return v;

  switch (ta) {
  case ACL_USER:
    qa = (uid_t *) acl_get_qualifier(a);
    qb = (uid_t *) acl_get_qualifier(b);
    v = (*qa-*qb);
    acl_free((void *) qa);
    acl_free((void *) qb);
    if (v)
      return v;
    break;
    
  case ACL_GROUP:
    qa = (uid_t *) acl_get_qualifier(a);
    qb = (uid_t *) acl_get_qualifier(b);
    v = (*qa-*qb);
    acl_free((void *) qa);
    acl_free((void *) qb);
    if (v)
      return v;
    break;

  default:
    break;
  }

  aet_a = aet_b = 0;
  
  /* Deny entries goes before allow ones */
  if (acl_get_entry_type_np(a, &aet_a) < 0)
    return -1;
  
  if (acl_get_entry_type_np(b, &aet_b) < 0)
    return 1;

  v = aet_b - aet_a;
  if (v)
    return v;

  return 0;
}


/* 
 * foreach CLASS (implicit, inherited)
 *   foreach TAG (owner@, user:uid, group@, group:gid, everyone@)
 *     foreach ID (x)
 *       foreach TYPE (deny, allow)
 */
acl_t
acl_sort(acl_t ap) {
  acl_t nap;


  nap = acl_dup(ap);
  if (!nap)
    return NULL;

  qsort(&nap->ats_acl.acl_entry[0], nap->ats_acl.acl_cnt, sizeof(nap->ats_acl.acl_entry[0]), acl_entry_compare);
  return nap;
}



/* Compare two ACLs */
int
acl_equal(acl_t aa,
	  acl_t ab) {
    acl_entry_t ea, eb;
    int ra, rb, rc;


    ra = acl_get_entry(aa, ACL_FIRST_ENTRY, &ea);
    rb = acl_get_entry(ab, ACL_FIRST_ENTRY, &eb);
  
    while (ra == 1 && rb == 1) {
	acl_tag_t tta, ttb;
	uid_t *uidap, *uidbp;
	gid_t *gidap, *gidbp;
	acl_permset_t pa, pb;
	acl_flagset_t fa, fb;
	acl_entry_type_t eta, etb;

	if (acl_get_tag_type(ea, &tta) < 0)
	    return -1;
    
	if (acl_get_tag_type(eb, &ttb) < 0)
	    return -2;
    
	if (tta != ttb)
	    return 0;

	switch (tta) {
	case ACL_USER:
	    uidap = (uid_t *) acl_get_qualifier(ea);
	    uidbp = (uid_t *) acl_get_qualifier(eb);
	    rc = (*uidap != *uidbp);
	    acl_free((void *) uidap);
	    acl_free((void *) uidbp);
	    if (rc)
		return 0;
	    break;

	case ACL_GROUP:
	    gidap = (gid_t *) acl_get_qualifier(ea);
	    gidbp = (gid_t *) acl_get_qualifier(eb);
	    rc = (*gidap != *gidbp);
	    acl_free((void *) gidap);
	    acl_free((void *) gidbp);
	    if (rc)
		return 0;
	    break;
	}

	if (acl_get_permset(ea, &pa) < 0)
	    return -1;
	if (acl_get_permset(eb, &pb) < 0)
	    return -2;
	if (*pa != *pb)
	    return 0;
    
	if (acl_get_flagset_np(ea, &fa) < 0)
	    return -1;
	if (acl_get_flagset_np(eb, &fb) < 0)
	    return -2;
	if (*fa != *fb)
	    return 0;
    

	if (acl_get_entry_type_np(ea, &eta) < 0)
	    return -1;
	if (acl_get_entry_type_np(eb, &etb) < 0)
	    return -2;
	if (eta != etb)
	    return 0;
    
	ra = acl_get_entry(aa, ACL_NEXT_ENTRY, &ea);
	rb = acl_get_entry(ab, ACL_NEXT_ENTRY, &eb);
    }

    if (ra == 0 && rb == 0)
	return 1;

    if (ra < 0 || rb < 0)
	return -3;
  
    return 0;
}


int
fix_acl(acl_t a,
	const char *path,
	uid_t fuid,
	gid_t fgid) {
    acl_entry_t aep;
    int eid;
    int acl_modified = 0;
    int have_everyone = 0;
    uid_t *uidp;
    gid_t *gidp;
    

    eid = ACL_FIRST_ENTRY;
    while (acl_get_entry(a, eid, &aep) > 0) {
	acl_tag_t tt;
    
	eid = ACL_NEXT_ENTRY;
    
	if (acl_get_tag_type(aep, &tt) < 0) {
	    fprintf(stderr, "%s: Error: acl_get_tag_type: %s\n",
		    argv0, strerror(errno));
	    exit(1);
	}

	switch (tt) {
	case ACL_EVERYONE:
	    have_everyone++;
	    break;
      
	case ACL_USER_OBJ:
	    if (fuid != -1) {
		/* Change user@ to a user: ACL entry */
		acl_set_tag_type(aep, ACL_USER);
		acl_set_qualifier(aep, (const void *) &fuid);
	
		acl_modified++;
		if (f_verbose > 1)
		    printf("%s: owner@ -> user:%d: ACL Entry updated\n", path, fuid);
	    }
	    break;
      
	case ACL_GROUP_OBJ:
	    if (fgid != -1) {
		/* Change group@ to a group: ACL entry */
		acl_set_tag_type(aep, ACL_GROUP);
		acl_set_qualifier(aep, (const void *) &fgid);
	
		acl_modified++;
		if (f_verbose > 1)
		    printf("%s: group@ -> group:%u: ACL Entry updated\n", path, fgid);
	    }
	    break;
      
	case ACL_USER:
	    uidp = (uid_t *) acl_get_qualifier(aep);
      
	    if (*uidp == ouid) {
		if (acl_set_qualifier(aep, (void *) &fuid) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_set_qualifier(%d -> %d): %s\n",
			    argv0, path, ouid, fuid, strerror(errno));
		    exit(1);
		}
	
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: user:%u -> user:%u: ACL Entry updated\n", path, ouid, fuid);
	    } else if (f_cleanup) {
		struct passwd *pp = getpwuid(*uidp);
	
		if (!pp) {
		    if (acl_delete_entry(a, aep) < 0) {
			fprintf(stderr, "%s: Error: %s: acl_delete_entry(user:%d): %s\n",
				argv0, path, *uidp, strerror(errno));
			exit(1);
		    } else {
			if (f_verbose > 1)
			    printf("%s: user:%u: ACL Entry Deleted [stale]\n", path, *uidp);
		    }
		}
	    }
	    acl_free(uidp);
	    break;

	case ACL_GROUP:
	    gidp = (gid_t *) acl_get_qualifier(aep);

	    if (*gidp == ogid) {
		if (acl_set_qualifier(aep, (void *) &fgid) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_set_qualifier(%d -> %d): %s\n",
			    argv0, path, ogid, fgid, strerror(errno));
		    exit(1);
		}
	
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: group:%d -> group:%d: ACL Entry updated\n", path, ogid, fgid);
	    } else if (f_cleanup) {
		struct group *gp = getgrgid(*gidp);
	
		if (!gp) {
		    if (acl_delete_entry(a, aep) < 0) {
			fprintf(stderr, "%s: Error: %s: acl_delete_entry(group:%d): %s\n",
				argv0, path, *gidp, strerror(errno));
			exit(1);
		    }
	  
		    acl_modified = 1;
		    if (f_verbose > 1)
			printf("%s: group:%d: ACL Entry Deleted [stale]\n", path, *gidp);
		}
	    }
	    break;
	}
    }
  
    if (f_everyone && !have_everyone) {
	acl_permset_t perms;
	acl_flagset_t flags;

	
	acl_create_entry(&a, &aep);
	acl_set_tag_type(aep, ACL_EVERYONE);
    
	acl_get_permset(aep, &perms);
	acl_clear_perms(perms);
	acl_set_permset(aep, perms);

	acl_get_flagset_np(aep, &flags);
	acl_clear_flags_np(flags);
	acl_set_flagset_np(aep, flags);
    
	acl_set_entry_type_np(aep, ACL_ENTRY_TYPE_ALLOW);
    
	acl_modified = 1;
	if (f_verbose > 1)
	    printf("%s: everyone@:::allow: ACL Entry added\n", path);
    }

    return acl_modified;
}



int
walker(const char *path,
       const struct stat *sp,
       int flags,
       struct FTW *fp) {
    uid_t fuid;
    gid_t fgid;
    acl_t a = NULL, na = NULL;
    int acl_modified = 0;
    

    ++n_file;
    if (f_verbose > 1) {
	if (f_verbose > 2)
	    printf("%s [base=%d, level=%d, size=%lu, uid=%u, gid=%u]:\n",
		   path,
		   fp->base, fp->level,
		   sp->st_size, sp->st_uid, sp->st_gid);
	else
	    printf("%s\n", path);
    }

    fuid = sp->st_uid;
    if (sp->st_uid == ouid) {
	n_chuid++;
	if (f_update) {
	    if (lchown(path, nuid, -1) < 0) {
		fprintf(stderr, "%s: Error: %s: chown(uid=%d): %s\n",
			argv0, path, nuid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose)
		printf("%s: Owner Updated\n", path);
	} else {
	    if (f_verbose)
		printf("%s: Owner (NOT) Updated\n", path);
	}
	fuid = nuid;
    }
  
    fgid = sp->st_gid;
    if (sp->st_gid == ogid) {
	n_chgrp++;
	if (f_update) {
	    if (lchown(path, -1, ngid) < 0) {
		fprintf(stderr, "%s: Error: %s: chown(gid=%d): %s\n",
			argv0, path, ngid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose)
		printf("%s: Group Updated\n", path);
	} else {
	    if (f_verbose)
		printf("%s: Group (NOT) Updated\n", path);
	}
	fgid = ngid;
    }

    na = a = acl_get_link_np(path, ACL_TYPE_NFS4);
    if (!a)
	return 0;

    if (f_propagate) {
	/* Propagate ACL inheritance down the tree */
	
	if (fp->level == 0) {
	    /* First level, set flags f+d */
	    acl_entry_t aep;
	    int eid;


	    acl_modified = fix_acl(a, path, f_user ? fuid : -1, f_group ? fgid : -1);

	    if (f_merge) {
		if (acl_merge(a) > 0) {
		    if (f_verbose > 1)
			printf("%s: ACL Merged\n", path);
		    acl_modified = 1;
		}
	    }
	    
	    if (f_sort) {
		na = acl_sort(a);
		if (acl_equal(a, na) == 0) {
		    acl_modified = 1;
		    acl_free(a);
		    a = na;
		    if (f_verbose > 1)
			printf("%s: ACL Sorted\n", path);
		} else
		    acl_free(na);
	    }
    
	    if (flags == FTW_D) {
		/* Only do this if starting with a directory */

		eid = ACL_FIRST_ENTRY;
		while (acl_get_entry(a, eid, &aep) > 0) {
		    acl_flagset_t flags;
		    

		    acl_get_flagset_np(aep, &flags);
		    if (acl_get_flag_np(flags, ACL_ENTRY_FILE_INHERIT) != 1) {
			acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
			acl_modified = 1;
		    }
		    if (acl_get_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT) != 1) {
			acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT);
			acl_modified = 1;
		    }
		    acl_set_flagset_np(aep, flags);
	
		    eid = ACL_NEXT_ENTRY;
		}

		
		/* Setup ACLs for subdirectories (f+d+I) and files (I) */
		
		saved_dir_acl = acl_dup(a);
		eid = ACL_FIRST_ENTRY;
		while (acl_get_entry(saved_dir_acl, eid, &aep) > 0) {
		    acl_flagset_t flags;
	
		    acl_get_flagset_np(aep, &flags);
		    acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
		    acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT);
		    acl_add_flag_np(flags, ACL_ENTRY_INHERITED);
		    acl_set_flagset_np(aep, flags);
	
		    eid = ACL_NEXT_ENTRY;
		}

		saved_file_acl = acl_dup(a);
		eid = ACL_FIRST_ENTRY;
		while (acl_get_entry(saved_file_acl, eid, &aep) > 0) {
		    acl_flagset_t flags;
	
		    acl_get_flagset_np(aep, &flags);
		    acl_delete_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
		    acl_delete_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT);
		    acl_add_flag_np(flags, ACL_ENTRY_INHERITED);
		    acl_set_flagset_np(aep, flags);
	
		    eid = ACL_NEXT_ENTRY;
		}
	    }
	} else {
	    /* Next levels down while propagating ACLs */
	    
	    na = (flags == FTW_D ? saved_dir_acl : saved_file_acl);
	    if (acl_equal(a, na) == 0)
		acl_modified = 1;
	}
    } else {
	/* No ACL inheritance propagation */
	acl_modified = fix_acl(a, path, f_user ? fuid : -1, f_group ? fgid : -1);

	if (f_merge) {
	    if (acl_merge(a) > 0) {
		if (f_verbose > 1)
		    printf("%s: ACL Merged\n", path);
		acl_modified = 1;
	    }
	}
	
	if (f_sort) {
	    na = acl_sort(a);
	    if (acl_equal(a, na) == 0) {
		acl_modified = 1;
		acl_free(a);
		a = na;
		if (f_verbose > 1)
		    printf("%s: ACL Sorted\n", path);
	    } else
		acl_free(na);
	}
    }

    if (acl_modified) {
	if (f_update) {
	    if (acl_set_link_np(path, ACL_TYPE_NFS4, na) < 0) {
		fprintf(stderr, "%s: Error: %s: acl_set_link_np: %s\n",
			argv0, path, strerror(errno));
		exit(1);
	    }
	    if (f_verbose)
		printf("%s: ACL Updated\n", path);
	} else {
	    if (f_verbose)
		printf("%s: ACL (NOT) Updated\n", path);
	}
	n_chacl++;
    }

    acl_free(a);
    return !f_recurse;
}





int
get_user_mapping(char *sp,
		 uid_t *ouidp,
		 uid_t *nuidp) {
    struct passwd *pp;
    char *dp = strchr(sp, ':');

  
    if (dp)
	*dp++ = '\0';
    else {
	dp = sp;
	sp = NULL;
	*ouidp = -1;
    }

    if (sp) {
	pp = getpwnam(sp);
	if (pp)
	    *ouidp = pp->pw_uid;
	else if (sscanf(sp, "%d", ouidp) != 1)
	    return -1;
    }
  
    pp = getpwnam(dp);
    if (pp)
	*nuidp = pp->pw_uid;
    else if (sscanf(sp, "%d", nuidp) != 1)
	return -2;
  
    return 0;
}



int
get_group_mapping(char *sp,
		  gid_t *ogidp,
		  gid_t *ngidp) {
    struct group *gp;
    char *dp = strchr(sp, ':');

  
    if (dp)
	*dp++ = '\0';
    else {
	dp = sp;
	sp = NULL;
	*ogidp = -1;
    }

    if (sp) {
	gp = getgrnam(sp);
	if (gp)
	    *ogidp = gp->gr_gid;
	else if (sscanf(sp, "%d", ogidp) != 1)
	    return -1;
    }
  
    gp = getgrnam(dp);
    if (gp)
	*ngidp = gp->gr_gid;
    else if (sscanf(sp, "%d", ngidp) != 1)
	return -2;
  
    return 0;
}




int
main(int argc,
     char *argv[]) {
    int i, j, rc;
  

    argv0 = argv[0];
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	if (argv[i][1] == '\0' || (argv[i][1] == '-' && argv[i][2] == '\0')) {
	    ++i;
	    goto LastArg;
	}

	
	for (j = 1; argv[i][j]; j++) {
	    char *vp = NULL;
	    int c = argv[i][j];

	Again:
	    switch (c) {
	    case '-':
		vp = strchr(argv[i]+j+1, '=');
		if (vp)
		    *vp++ = '\0';
		if (strcmp(argv[i]+j+1, "help") == 0) {
		    c = 'h';
		    goto Again;
		}
		break;
		
	    case 'v':
		f_verbose++;
		break;

	    case 'r':
		f_recurse++;
		break;
		
	    case 'n':
		f_update = 0;
		break;

	    case 'u':
		f_user++;
		break;

	    case 'g':
		f_group++;
		break;

	    case 'c':
		f_cleanup++;
		break;
	
	    case 's':
		f_sort++;
		break;
	
	    case 'm':
		f_merge++;
		break;
	
	    case 'e':
		f_everyone++;
		break;

	    case 'p':
		f_propagate++;
		break;
	
	    case 'U':
		if (argv[i][j+1]) {
		    ++j;
		    rc = get_user_mapping(argv[i]+j, &ouid, &nuid);
		} else if (i+1 < argc) {
		    j = 0;
		    rc = get_user_mapping(argv[++i], &ouid, &nuid);
		}
		switch (rc) {
		case -1:
		    fprintf(stderr, "%s: Error: %s: Invalid user mapping (source)\n",
			    argv[0], argv[i]+j);
		    exit(1);
		case -2:
		    fprintf(stderr, "%s: Error: %s: Invalid user mapping (destination)\n",
			    argv[0], argv[i]+j);
		    exit(1);
		}
		goto NextArg;
	  
	    case 'G':
		if (argv[i][j+1]) {
		    ++j;
		    rc = get_group_mapping(argv[i]+j, &ogid, &ngid);
		} else if (i+1 < argc) {
		    j = 0;
		    rc = get_group_mapping(argv[++i], &ogid, &ngid);
		}
		switch (rc) {
		case -1:
		    fprintf(stderr, "%s: Error: %s: Invalid group mapping (source)\n",
			    argv[0], argv[i]+j);
		    exit(1);
		case -2:
		    fprintf(stderr, "%s: Error: %s: Invalid group mapping (destination)\n",
			    argv[0], argv[i]+j);
		    exit(1);
		}
		goto NextArg;
	  
	    case 'h':
		printf("Usage:\n  %s [<options>] <path>\n\n", argv[0]);
		puts("Options:");
		puts("  -h                Display this information");
		puts("  -v                Be more verbose");
		puts("  -n                No-update mode");
		puts("  -r                Recurse into subdirectories");
		puts("  -s                Sort ACL");
		puts("  -m                Merge redundant ACL entries");
		puts("  -u                Convert owner@ to user: entries");
		puts("  -g                Convert group@ to group: entries");
		puts("  -p                Propagate ACL inheritance");
		puts("  -c                Cleanup stale (numeric) user & group ACL entries");
		puts("  -e                Make sure special everyone@ entries exist");
		puts("  -U [<from>:]<to>  Define user remapping entry");
		puts("  -G [<from>:]<to>  Define group remapping entry");
		exit(0);
	
	    default:
		fprintf(stderr, "%s: Error: -%c: Invalid switch\n",
			argv[0], argv[i][j]);
		exit(1);
	    }
	}
    NextArg:;
    }
 LastArg:
    
    if (f_verbose)
	printf("[aclrepair, v%s - Copyright (c) 2023 Peter Eriksson <pen@lysator.liu.se>]\n",
	       version);
    
    if (i >= argc) {
	fprintf(stderr, "%s: Error: Missing required path(s)\n",
		argv[0]);
	exit(1);
    }
  
    while (i < argc) {
	if (nftw(argv[i], walker, 1024, FTW_MOUNT) < 0) {
	    fprintf(stderr, "%s: Error: %s: nftw: %s\n",
		    argv[0], argv[i], strerror(errno));
	    exit(1);
	}
    
	++i;
    }

    if (f_verbose)
	printf("[%u Scanned: %d User + %d Group Owner%s, %d ACL Entr%s %sChanged; %d Warning%s]\n",
	       n_file, n_chuid, n_chgrp,
	       (n_chuid+n_chgrp) == 1 ? "" : "s",
	       n_chacl, n_chacl == 1 ? "y" : "ies",
	       f_update ? "" : "(NOT) ",
	       n_warn, n_warn == 1 ? "" : "s");
    return 0;
}
