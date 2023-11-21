/*
 * aclrepair.c
 *
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
#include <arpa/inet.h>
#include <sys/extattr.h>

#include "acls.h"
#include "argv.h"


char *version = "0.5";

int f_dryrun = 0;
int f_verbose = 0;
int f_force = 0;
int f_debug = 0;
int f_ignore = 0;
int f_warn = 0;
int f_owner = 0;
int f_group = 0;
int f_everyone = 0;
int f_propagate = 0;
int f_backup = 0;
int f_restore = 0;
int f_zero = 0;
int f_cleanup = 0;
int f_sort = 0;
int f_merge = 0;
int f_recurse = 0;

int f_adopt_stale_user_owner = 0;
int f_adopt_stale_group_owner = 0;

acl_t inherited_dir_acl = NULL;
acl_t inherited_file_acl = NULL;

char *argv0 = "aclrepair";

int n_chuid = 0;
int n_chgrp = 0;
int n_chacl = 0;
int n_file = 0;
int n_warn = 0;

char *attr_saved_uid = "se.liu.it.aclrepair.saved_uid";
char *attr_saved_gid = "se.liu.it.aclrepair.saved_gid";
char *attr_saved_acl = "se.liu.it.aclrepair.saved_acl";


struct uidmap {
    uid_t old;
    uid_t new;
    struct uidmap *next;
} *uidmap = NULL;

struct gidmap {
    gid_t old;
    gid_t new;
    struct gidmap *next;
} *gidmap = NULL;


int
uidmap_lookup(uid_t ou,
	      uid_t *nu) {
    struct uidmap *ump;
    
    for (ump = uidmap; ump && ump->old != ou; ump = ump->next)
	;
    if (ump) {
	*nu = ump->new;
	return 1;
    }

    return 0;
}


int
gidmap_lookup(gid_t og,
	      gid_t *ng) {
    struct gidmap *gmp;
    
    for (gmp = gidmap; gmp && gmp->old != og; gmp = gmp->next)
	;
    if (gmp) {
	*ng = gmp->new;
	return 1;
    }

    return 0;
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
    else if (sscanf(dp, "%d", nuidp) != 1)
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
    else if (sscanf(dp, "%d", ngidp) != 1)
	return -2;
  
    return 0;
}


int
uidmap_add(char *s,
	   void *vp,
	   void *dp) {
    struct uidmap *ump, **head = vp;
    int rc;

    
    ump = malloc(sizeof(*ump));
    if (!ump)
	return -1;
    
    rc = get_user_mapping(s, &ump->old, &ump->new);
    if (rc < 0) {
	free(ump);
	return rc;
    }

    if (ump->old == -1)
	f_adopt_stale_user_owner = 1;
    
    ump->next = *head;
    *head = ump;
    return 0;
}

int
gidmap_add(char *s,
	   void *vp,
	   void *dp) {
    struct gidmap *gmp, **head = vp;
    int rc;
    
    gmp = malloc(sizeof(*gmp));
    if (!gmp)
	return -1;
    
    rc = get_group_mapping(s, &gmp->old, &gmp->new);
    if (rc < 0) {
	free(gmp);
	return rc;
    }

    if (gmp->old == -1)
	f_adopt_stale_group_owner = 1;
    
    gmp->next = *head;
    *head = gmp;
    return 0;
}



int
fix_acl(acl_t a,
	const char *path,
	const struct stat *sp) {
    acl_entry_t aep;
    int eid;
    int acl_modified = 0;
    int have_everyone = 0;
    uid_t *uidp, fuid;
    gid_t *gidp, fgid;
    struct passwd *pp;
    struct group *gp;
		
    

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
	    if (f_owner) {
		/* Change user@ to a user: ACL entry */
		acl_set_tag_type(aep, ACL_USER);
		fuid = sp->st_uid;
		uidmap_lookup(sp->st_uid, &fuid);
		acl_set_qualifier(aep, (const void *) &fuid);
		acl_modified++;
		if (f_verbose > 1)
		    printf("%s: owner@ -> user:%d: ACL Entry updated\n", path, fuid);
	    }
	    break;
      
	case ACL_GROUP_OBJ:
	    if (f_group) {
		/* Change group@ to a group: ACL entry */
		acl_set_tag_type(aep, ACL_GROUP);
		fgid = sp->st_gid;
		gidmap_lookup(sp->st_uid, &fgid);
		acl_set_qualifier(aep, (const void *) &fgid);
		acl_modified++;
		if (f_verbose > 1)
		    printf("%s: group@ -> group:%u: ACL Entry updated\n", path, fgid);
	    }
	    break;
      
	case ACL_USER:
	    uidp = (uid_t *) acl_get_qualifier(aep);
	    if (!uidp) {
		fprintf(stderr, "%s: Error: Unable to get user: qualifier: %s\n",
			argv0, strerror(errno));
		exit(1);
	    }

	    if (f_cleanup || f_adopt_stale_user_owner)
		pp = getpwuid(*uidp);
	    else
		pp = NULL;
	    
	    if (uidmap_lookup(*uidp, &fuid) == 1 ||
		(f_adopt_stale_user_owner && !pp && uidmap_lookup(-1, &fuid) == 1)) {
		if (acl_set_qualifier(aep, (void *) &fuid) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_set_qualifier(%d -> %d): %s\n",
			    argv0, path, *uidp, fuid, strerror(errno));
		    exit(1);
		}
	
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: user:%u -> user:%u: ACL Entry updated\n", path, *uidp, fuid);
	    } else if (f_cleanup && !pp) {
		if (acl_delete_entry(a, aep) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_delete_entry(user:%d): %s\n",
			    argv0, path, *uidp, strerror(errno));
		    exit(1);
		} else {
		    if (f_verbose > 1)
			printf("%s: user:%u: ACL Entry Deleted [stale]\n", path, *uidp);
		}
	    }
	    acl_free(uidp);
	    break;

	case ACL_GROUP:
	    gidp = (gid_t *) acl_get_qualifier(aep);
	    if (!gidp) {
		fprintf(stderr, "%s: Error: Unable to get group: qualifier: %s\n",
			argv0, strerror(errno));
		exit(1);
	    }
		
	    if (f_cleanup || f_adopt_stale_group_owner)
		gp = getgrgid(*gidp);
	    else
		gp = NULL;
	    
	    if (gidmap_lookup(*gidp, &fgid) == 1 ||
		(f_adopt_stale_group_owner && !gp && gidmap_lookup(-1, &fgid) == 1)) {
		if (acl_set_qualifier(aep, (void *) &fgid) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_set_qualifier(%d -> %d): %s\n",
			    argv0, path, *gidp, fgid, strerror(errno));
		    exit(1);
		}
		
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: group:%d -> group:%d: ACL Entry updated\n", path, *gidp, fgid);
	    } else if (f_cleanup) {
		if (acl_delete_entry(a, aep) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_delete_entry(group:%d): %s\n",
			    argv0, path, *gidp, strerror(errno));
		    exit(1);
		}
		
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: group:%d: ACL Entry Deleted [stale]\n", path, *gidp);
	    }
	    acl_free(gidp);
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


void
spin(void) {
    const char dials[] = "|/-\\";
    static time_t last;
    time_t now;

    if (isatty(1)) {
	time(&now);
	if (now != last) {
	    last = now;
	    putc(dials[now%sizeof(dials)-1], stdout);
	    putc('\b', stdout);
	    fflush(stdout);
	}
    }
}

int
walker(const char *path,
       const struct stat *sp,
       int flags,
       struct FTW *fp) {
    uid_t fuid = -1;
    gid_t fgid = -1;
    acl_t a = NULL;
    int acl_modified = 0;
    struct stat sb;
    uid_t saved_uid = -1;
    gid_t saved_gid = -1;
    acl_t saved_acl = NULL;
    

    switch (flags) {
    case FTW_DNR:
	if (f_ignore)
	    return 0;

	fprintf(stderr, "%s: Error: %s: Unable to descend into directory\n",
		argv0, path);
	exit(1);
	
    case FTW_NS:
	if (f_ignore)
	    return 0;
	fprintf(stderr, "%s: Error: %s: Unreadable file attributes\n",
		argv0, path);
	exit(1);
    }
    
    ++n_file;

    if (f_verbose > 2) {
	if (f_verbose > 3)
	    printf("%s [flags=%d, base=%d, level=%d, size=%lu, uid=%u, gid=%u]:\n",
		   path,
		   flags,
		   fp->base, fp->level,
		   sp->st_size, sp->st_uid, sp->st_gid);
	else
	    printf("%s\n", path);
    } else
	spin();

    /* Get current ACL protecting object */
    a = acl_get_link_np(path, ACL_TYPE_NFS4);
    if (!a) {
	fprintf(stderr, "%s: Error: %s: Reading ACL: %s\n",
		argv0, path, strerror(errno));
	exit(1);
    }
    
    if (f_restore > 0) {
	/* Restore saved Owner UID & GID and ACL from Extended Attribute */
	char *as;
	ssize_t aslen, rlen;


	/* Stored Backup Owner UID */
	if ((rlen = extattr_get_link(path, EXTATTR_NAMESPACE_USER,
				     attr_saved_uid,
				     &saved_uid, sizeof(saved_uid))) < 0 ||
	    rlen != sizeof(saved_uid)) {
	    
	    /* Ignore if no backup data found */
	    if (rlen >= 0 || errno != ENOATTR) {
		fprintf(stderr, "%s: Error: %s: %s: Reading Backup Owner UID: %s\n",
			argv0, path, attr_saved_uid, rlen < 0 ? strerror(errno) : "Invalid size");
		exit(1);
	    }
	    if (f_warn)
		fprintf(stderr, "%s: Warning: %s: %s: Restoring Backup Owner UID: No backup data found\n",
			argv0, path, attr_saved_uid);
	} else {
	    saved_uid = ntohl(saved_uid);
	    
	    if (sp->st_uid != saved_uid) {
		if (!f_dryrun) {
		    if (lchown(path, saved_uid, -1) < 0) {
			fprintf(stderr, "%s: Error: %s: Restoring Owner UID: chown(uid=%d): %s\n",
				argv0, path, saved_uid, strerror(errno));
			exit(1);
		    }
		    if (f_verbose)
			printf("%s: Owner UID Restored\n", path);
		} else {
		    if (f_verbose)
			printf("%s: Owner UID (NOT) Restored\n", path);
		}
	    }
	}

	/* Stored Backup Owner GID */
	if ((rlen = extattr_get_link(path, EXTATTR_NAMESPACE_USER,
				     attr_saved_gid,
				     &saved_gid, sizeof(saved_gid))) < 0 ||
	    rlen != sizeof(saved_uid)) {
	    
	    /* Ignore if no backup data found */
	    if (rlen >= 0 || errno != ENOATTR) {
		fprintf(stderr, "%s: Error: %s: %s: Reading Backup Owner GID: %s\n",
			argv0, path, attr_saved_gid, rlen < 0 ? strerror(errno) : "Invalid size");
		exit(1);
	    }
	    if (f_warn)
		fprintf(stderr, "%s: Warning: %s: %s: Restoring Backup Owner GID: No backup data found\n",
			argv0, path, attr_saved_gid);
	} else {
	    saved_gid = ntohl(saved_gid);
	    
	    if (sp->st_gid != saved_gid) {
		if (!f_dryrun) {
		    if (lchown(path, -1, saved_gid) < 0) {
			fprintf(stderr, "%s: Error: %s: Restoring Owner GID: chown(gid=%d): %s\n",
				argv0, path, saved_gid, strerror(errno));
			exit(1);
		    }
		    if (f_verbose)
			printf("%s: Owner GID Restored\n", path);
		} else {
		    if (f_verbose)
			printf("%s: Owner GID (NOT) Restored\n", path);
		}
	    }
	}

	
	/* Stored Backup ACL */
	aslen = extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr_saved_acl, NULL, 0);
	if (aslen < 0) {
	    fprintf(stderr, "%s: Error: %s: %s: Reading Backup ACL: %s\n",
		    argv0, path, attr_saved_acl, strerror(errno));
	    exit(1);
	}
	
	as = malloc(aslen);
	if (!as) {
	    fprintf(stderr, "%s: Error: %lu: Memory allocation error: %s\n",
		    argv0, aslen, strerror(errno));
	    exit(1);
	}

	/* Get stored ACL */
	if ((rlen = extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr_saved_acl, as, aslen)) < 0 ||
	    rlen != aslen) {
	    if (rlen >= 0|| errno != ENOATTR) { 
		fprintf(stderr, "%s: Error: %s: %s: Reading Backup ACL: %s\n", 
			argv0, path, attr_saved_gid, rlen < 0 ? strerror(errno) : "Invalid size");
		exit(1);
	    }
	    if (f_warn)
		fprintf(stderr, "%s: Warning: %s: %s: Restoring Backup ACL: No backup data found\n",
			argv0, path, attr_saved_acl);
	} else {
	    saved_acl = acl_from_text(as);
	    if (!saved_acl) {
		fprintf(stderr, "%s: Error: %s: %s: Restoring Backup ACL: Parse failure: %s\n",
			argv0, path, attr_saved_acl,
			strerror(errno));
		fprintf(stderr, "ACL:\n%s\n", as);
		exit(1);
	    }
	    free(as);
	}
    }
    

    if (f_backup > 0) {
	/* Stored Backup Owner UID in Extended Attribute */
	if (!f_force && extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr_saved_uid, NULL, 0) >= 0) {
	    fprintf(stderr, "%s: Error: %s: %s: Stored Backup UID: Already exists\n",
		    argv0, path, attr_saved_uid);
	    exit(1);
	}
	    
	if (!f_dryrun) {
	    uid_t uid = htonl(sp->st_uid);
	    
	    if (extattr_set_link(path, EXTATTR_NAMESPACE_USER, attr_saved_uid, &uid, sizeof(uid)) < 0) {
		fprintf(stderr, "%s: Error: %s: %s: Storing Backup UID: %s\n",
			argv0, path, attr_saved_uid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose > 1)
		printf("%s: Stored Backup Owner UID\n", path);
	} else {
	    if (f_verbose > 1)
		printf("%s: (NOT) Stored Backup Owner UID\n", path);
	}
	
	
	/* Stored Backup Owner GID in Extended Attribute */
	if (!f_force && extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr_saved_gid, NULL, 0) >= 0) {
	    fprintf(stderr, "%s: Error: %s: %s: Stored Backup GID: Already exists\n",
		    argv0, path, attr_saved_gid);
	    exit(1);
	}
	
	if (!f_dryrun) {
	    gid_t gid = htonl(sp->st_gid);
	
	    if (extattr_set_link(path, EXTATTR_NAMESPACE_USER, attr_saved_gid, &gid, sizeof(gid)) < 0) {
		fprintf(stderr, "%s: Error: %s: %s: Storing Backup GID: %s\n",
			argv0, path, attr_saved_gid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose > 1)
		printf("%s: Stored Backup Owner GID\n", path);
	} else {
	    if (f_verbose > 1)
		printf("%s: (NOT) Stored Backup Owner GID\n", path);
	}
	
	/* Store Backup ACL in Extended Attribute */
	if (a) {
	    char *as;
	    ssize_t alen = 0;

	    as = acl_to_text_np(a, &alen, ACL_TEXT_NUMERIC_IDS);
	    if (!as) {
		fprintf(stderr, "%s: Error: %s: Failure converting ACL to text: %s\n",
			argv0, path, strerror(errno));
		exit(1);
	    }
	    
	    if (!f_force && extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr_saved_acl, NULL, 0) >= 0) {
		fprintf(stderr, "%s: Error: %s: %s: Stored Backup ACL already exists\n",
			argv0, path, attr_saved_acl);
		exit(1);
	    }
		
	    if (!f_dryrun) {
		if (extattr_set_link(path, EXTATTR_NAMESPACE_USER, attr_saved_acl, as, alen+1) < 0) {
		    fprintf(stderr, "%s: Error: %s: %s: Storing Backup ACL: %s\n",
			    argv0, path, attr_saved_acl, strerror(errno));
		    exit(1);
		}
		if (f_verbose > 1)
		    printf("%s: Stored Backup ACL\n", path);
	    } else {
		if (f_verbose > 1)
		    printf("%s: (NOT) Stored Backup ACL\n", path);
	    }
	    acl_free(as);
	}
    } else if (f_backup < 0) {
	/* Remove ACL backup extended attributes */
	if (!f_dryrun) {
	    int rc;
	    
	    if ((rc = extattr_delete_link(path, EXTATTR_NAMESPACE_USER, attr_saved_uid)) < 0 && errno != ENOATTR) {
		fprintf(stderr, "%s: Error: %s: %s: Removing Backup UID: %s\n",
			argv0, path, attr_saved_uid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose && rc >= 0)
		printf("%s: Removed Backup UID\n", path);
	} else {
	    if (f_verbose)
		printf("%s: (NOT) Removed Backup UID\n", path);
	}
	if (!f_dryrun) {
	    int rc;
	    
	    if ((rc = extattr_delete_link(path, EXTATTR_NAMESPACE_USER, attr_saved_gid)) < 0 && errno != ENOATTR) {
		fprintf(stderr, "%s: Error: %s: %s: Removing Backup GID: %s\n",
			argv0, path, attr_saved_gid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose && rc >= 0)
		printf("%s: Removed Backup GID\n", path);
	} else {
	    if (f_verbose)
		printf("%s: (NOT) Removed Backup GID\n", path);
	}
	
	if (!f_dryrun) {
	    int rc;
	    
	    if ((rc = extattr_delete_link(path, EXTATTR_NAMESPACE_USER, attr_saved_acl)) < 0 && errno != ENOATTR) {
		fprintf(stderr, "%s: Error: %s: %s: Removing Backup ACL: %s\n",
			argv0, path, attr_saved_acl, strerror(errno));
		exit(1);
	    }
	    if (f_verbose && rc >= 0)
		printf("%s: Removed Backup ACL\n", path);
	} else {
	    if (f_verbose)
		printf("%s: (NOT) Removed Backup ACL\n", path);
	}
    }


    /* We do this after a potential backup operation in order to allow swapping current & backup */
    if (f_restore) {
	/* Refresh stat information */
	if (sp->st_uid != saved_uid || sp->st_gid != saved_gid) {
	    if (lstat(path, &sb) < 0) {
		fprintf(stderr, "%s: Error: %s: lstat: %s\n",
			argv0, path, strerror(errno));
		exit(1);
	    }
	    sp = &sb;
	}

	if (acl_equal(a, saved_acl) != 1) {
	    /* Update stored ACL */
	    if (!f_dryrun) {
		if (acl_set_link_np(path, ACL_TYPE_NFS4, saved_acl) < 0) {
		    fprintf(stderr, "%s: Error: %s: acl_set_link_np: %s\n",
			    argv0, path, strerror(errno));
		    exit(1);
		}
		if (f_verbose)
		    printf("%s: Restored ACL\n", path);
	    } else {
		if (f_verbose)
		    printf("%s: (NOT) Restored ACL\n", path);
	    }
	    
	    acl_modified = 1;
	}

	acl_free(a);
	a = saved_acl;
    }

    
    if (uidmap_lookup(sp->st_uid, &fuid) == 1 ||
	(f_adopt_stale_user_owner && getpwuid(sp->st_uid) == NULL && uidmap_lookup(-1, &fuid) == 1)) {
	n_chuid++;
	if (!f_dryrun) {
	    if (lchown(path, fuid, -1) < 0) {
		fprintf(stderr, "%s: Error: %s: chown(uid=%d): %s\n",
			argv0, path, fuid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose)
		printf("%s: User Owner Updated\n", path);
	} else {
	    if (f_verbose)
		printf("%s: User Owner (NOT) Updated\n", path);
	}
    }
    if (gidmap_lookup(sp->st_gid, &fgid) == 1 ||
	(f_adopt_stale_group_owner && getgrgid(sp->st_gid) == NULL && gidmap_lookup(-1, &fgid) == 1)) {
	n_chgrp++;
	if (!f_dryrun) {
	    if (lchown(path, -1, fgid) < 0) {
		fprintf(stderr, "%s: Error: %s: chown(gid=%d): %s\n",
			argv0, path, fgid, strerror(errno));
		exit(1);
	    }
	    if (f_verbose)
		printf("%s: Group Owner Updated\n", path);
	} else {
	    if (f_verbose)
		printf("%s: Group Owner (NOT) Updated\n", path);
	}
    }

    if (f_propagate) {
	/* Propagate ACL inheritance down the tree */
	
	if (fp->level == 0) {
	    /* First level, set flags f+d */
	    acl_entry_t ae;
	    int eid;


	    acl_modified = fix_acl(a, path, sp);

	    if (f_merge) {
		if (acl_merge(a) > 0) {
		    if (f_verbose > 1)
			printf("%s: ACL Merged\n", path);
		    acl_modified = 1;
		}
	    }
	    
	    if (f_sort) {
		acl_t na;

		na = acl_dup(a);
		acl_sort(na);
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
		inherited_dir_acl = acl_init(ACL_MAX_ENTRIES);
		inherited_file_acl = acl_init(ACL_MAX_ENTRIES);

		
		eid = ACL_FIRST_ENTRY;
		while (acl_get_entry(a, eid, &ae) > 0) {
		    acl_flagset_t af, df, ff;
		    acl_entry_t de, fe;
		    

		    acl_get_flagset_np(ae, &af);

		    /* Force propagation of all ACL entries */
		    if (f_propagate > 1) {
			acl_add_flag_np(af, ACL_ENTRY_FILE_INHERIT);
			acl_add_flag_np(af, ACL_ENTRY_DIRECTORY_INHERIT);
			acl_set_flagset_np(ae, af);
			acl_modified = 1;
		    }

		    /* Setup inherited subdirectory/file ACLs */
		    if (f_propagate) {
			if (acl_get_flag_np(af, ACL_ENTRY_FILE_INHERIT) == 1 ||
			    acl_get_flag_np(af, ACL_ENTRY_DIRECTORY_INHERIT) == 1) {
			    acl_create_entry(&inherited_file_acl, &fe);
			    acl_copy_entry(fe, ae);	
			    acl_get_flagset_np(fe, &ff);
			    acl_delete_flag_np(ff, ACL_ENTRY_FILE_INHERIT);
			    acl_delete_flag_np(ff, ACL_ENTRY_DIRECTORY_INHERIT);
			    acl_delete_flag_np(ff, ACL_ENTRY_NO_PROPAGATE_INHERIT);
			    acl_add_flag_np(ff, ACL_ENTRY_INHERITED);
			    acl_set_flagset_np(fe, ff);
			}
			
			if (acl_get_flag_np(af, ACL_ENTRY_DIRECTORY_INHERIT) == 1) {
			    acl_create_entry(&inherited_dir_acl, &de);
			    acl_copy_entry(de, ae);
			    acl_get_flagset_np(de, &df);
			    if (acl_get_flag_np(af, ACL_ENTRY_NO_PROPAGATE_INHERIT) == 1) {
				acl_delete_flag_np(df, ACL_ENTRY_FILE_INHERIT);
				acl_delete_flag_np(df, ACL_ENTRY_DIRECTORY_INHERIT);
				acl_delete_flag_np(df, ACL_ENTRY_NO_PROPAGATE_INHERIT);
			    }
			    acl_add_flag_np(df, ACL_ENTRY_INHERITED);
			    acl_set_flagset_np(de, df);
			}
		    }
	
		    eid = ACL_NEXT_ENTRY;
		}
	    }
	} else {
	    /* Next levels down while propagating ACLs */
	    acl_t aa;

	    
	    aa = (flags == FTW_D ? inherited_dir_acl : inherited_file_acl);
	    if (f_zero) {
		/* Discard all other ACL entries */
		if (acl_equal(a, aa) == 0) {
		    acl_free(a);
		    a = acl_dup(aa);
		    acl_modified = 1;
		}
	    } else {
		/* Merge propagated ACL entries with current ones */
		acl_t na = acl_dup(a);

		acl_join(na, aa);

		acl_modified = fix_acl(na, path, sp);
		
		if (f_merge)
		    acl_merge(na);	
	
		if (f_sort)
		    acl_sort(na);
		
		if (acl_equal(a, na) == 0) {
		    acl_free(a);
		    a = na;
		    acl_modified = 1;
		} else
		    acl_free(na);
	    }
	}
    } else {
	/* No ACL inheritance propagation */
	acl_modified = fix_acl(a, path, sp);

	if (f_merge) {
	    if (acl_merge(a) > 0) {
		acl_modified = 1;
		if (f_verbose > 1)
		    printf("%s: ACL Merged\n", path);
	    }
	}
	
	if (f_sort) {
	    acl_t na = acl_dup(a);
	    
	    acl_sort(na);
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
	if (!f_dryrun) {
	    if (f_debug)
		printf("%s: Setting ACL to:\n%s", path, acl_to_text(a, NULL));

	    if (acl_set_link_np(path, ACL_TYPE_NFS4, a) < 0) {
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
usage(char *s,
      void *vp,
      void *dp);


ARGVOPT options[] = {
    { 'h', "help",      NULL,            NULL,         usage,      "Display this information" },
    { 'v', "verbose",   NULL,            &f_verbose,   NULL,       "Be more verbose" },
    { 'w', "warning",   NULL,            &f_warn,      NULL,       "Enable warnings" },
    { 'f', "force",     NULL,            &f_force,     NULL,       "Force/overwrite mode" },
    { 'd', "debug",     NULL,            &f_debug,     NULL,       "Enable debugging output" },
    { 'i', "ignore",    NULL,            &f_ignore,    NULL,       "Ignore some soft errors" },
    { 'r', "recurse",   NULL,            &f_recurse,   NULL,       "Recurse into subdirectories/files" },
    { 'n', "dry-run",   NULL,            &f_dryrun,    NULL,       "No-update mode" },
    { 'o', "owner",     NULL,            &f_owner,     NULL,       "Convert owner@ to user: entries" },
    { 'g', "group",     NULL,            &f_group,     NULL,       "Convert group@ to group: entries" },
    { 'c', "cleanup",   NULL,            &f_cleanup,   NULL,       "Remove stale ACL entries" },
    { 's', "sort",      NULL,            &f_sort,      NULL,       "Sort ACL entries" },
    { 'm', "merge",     NULL,            &f_merge,     NULL,       "Merge redundant ACL entries" },
    { 'e', "everyone",  NULL,            &f_everyone,  NULL,       "Add everyone@ entry if it doesn't exist" },
    { 'p', "propagate", NULL,            &f_propagate, NULL,       "Propagate ACLs to subdirectories/files" },
    { 'z', "zero",      NULL,            &f_zero,      NULL,       "Zero out ACL before propagation" },
    { 'b', "backup",    NULL,            &f_backup,    NULL,       "Backup ACLs to Extended Attributes" },
    { 'u', "restore",   NULL,            &f_restore,   NULL,       "Restore ACLs from Extended Attributes" },
    { 'U', "usermap",   "[<from>:]<to>", &uidmap,      uidmap_add, "Add user mapping entry" },
    { 'G', "groupmap",  "[<from>:]<to>", &gidmap,      gidmap_add, "Add group mapping entry" },
    { 0,   NULL,        NULL,            NULL,         NULL,       NULL }
};


int
usage(char *s,
      void *vp,
      void *dp) {
    printf("Usage:\n  %s [<options>] <path> [.. <path-N>]\n\n", argv0);
    puts("Options:");
    argv_list_options(&options[0]);
    exit(0);
}


int
main(int argc,
     char *argv[]) {
    int i;

    
    argv0 = argv[0];

    argv_parse_options(&i, argc, argv, options);

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
	       f_dryrun ? "(NOT) " : "",
	       n_warn, n_warn == 1 ? "" : "s");
    return 0;
}
