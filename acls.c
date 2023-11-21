/*
 * acls.c
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

#include <stdlib.h>
#include "acls.h"


/* Compare two ACL Entries */
static int
_acl_entry_compare(const void *va,
		   const void *vb) {
  acl_entry_t a = (acl_entry_t) va;
  acl_entry_t b = (acl_entry_t) vb;
  acl_entry_type_t aet_a, aet_b;
  acl_tag_t ta, tb;
  acl_flagset_t afs, bfs;
  int v;
  int inherited_a, inherited_b;
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

  /* Compare the entries on the flags */
  v = *afs-*bfs;
  if (v)
      return v;
  
  return 0;
}

int
acl_entry_equal(acl_entry_t ea,
		acl_entry_t eb) {
    return _acl_entry_compare(ea, eb) == 0;
}


/* 
 * foreach CLASS (implicit, inherited)
 *   foreach TAG (owner@, user:uid, group@, group:gid, everyone@)
 *     foreach ID (x)
 *       foreach TYPE (deny, allow)
 */
int
acl_sort(acl_t ap) {
  qsort(&ap->ats_acl.acl_entry[0], ap->ats_acl.acl_cnt, sizeof(ap->ats_acl.acl_entry[0]),
	_acl_entry_compare);
  
  return ap->ats_acl.acl_cnt;
}



/* &nap->ats_acl.acl_entry[0], nap->ats_acl.acl_cnt */
int
acl_merge(acl_t a) {
    int i, j, k;
    int rc = 0;

    
    for (i = 0; i < a->ats_acl.acl_cnt; i++) {
	acl_entry_t ea;
	acl_permset_t pa;
	
	ea = &a->ats_acl.acl_entry[i];
	acl_get_permset(ea, &pa);

	/* Look for duplicate entries */
	for (j = i+1; j < a->ats_acl.acl_cnt; j++) {
	    acl_entry_t eb;
	    acl_permset_t pb;

	    eb = &a->ats_acl.acl_entry[j];
	    if (acl_entry_equal(ea, eb) != 1)
		continue;
	    
	    /* Same entry tag type, flags & type (allow/deny) */
	    acl_get_permset(eb, &pb);
	    *pa |= *pb;

	    for (k = j; k < a->ats_acl.acl_cnt-1; k++)
		a->ats_acl.acl_entry[k] = a->ats_acl.acl_entry[k+1];
	    a->ats_acl.acl_cnt--;
	    --j;
	    rc++;
	}
    }

    return rc;
}



int
acl_join(acl_t a,
	 acl_t b) {
    int i, rc;
    acl_entry_t ae, be;


    for (i = ACL_FIRST_ENTRY; (rc = acl_get_entry(b, i, &be)) == 1; i = ACL_NEXT_ENTRY) {
	if (acl_create_entry(&a, &ae) < 0)
	    return -1;
	if (acl_copy_entry(ae, be) < 0)
	    return -1;
    }

    return rc;
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
