/*
 * argv.c
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
#include <sysexits.h>

#include "argv.h"

void
argv_list_options(ARGVOPT *options) {
    int i;
    
    for (i = 0; options[i].s; i++) {
	char *a = options[i].a;
	
	if (!a) {
	    if (options[i].v && !options[i].p)
		a = "[-|<num>]";
	    else
		a = "";
	}
	printf("  -%c, --%-10s  %-16s  %s\n",
	       options[i].c, options[i].s, a, options[i].h);
    }
}


static int
int_get(char *s,
	void *vp,
	void *dp) {
    int *ip = vp;
    

    if (!s || strcmp(s, "+") == 0) {
	*ip += (dp ? * (int *) dp : 1);
	return 1;
    }

    if (strcmp(s, "-") == 0) {
	*ip -= (dp ? * (int *) dp : 1);
	return 1;
    }
    
    if (strcmp(s, "no") == 0 ||
	strcmp(s, "off") == 0 ||
	strcmp(s, "false") == 0) {
	*ip = 0;
	return 1;
    }

    if (strcmp(s, "yes") == 0 ||
	strcmp(s, "on") == 0 ||
	strcmp(s, "true") == 0) {
	*ip = 1;
	return 1;
    }

    return sscanf(s, "%d", ip);
}




int
argv_parse_options(int *ip,
		   int argc,
		   char **argv,
		   ARGVOPT *options) {
    int j, k, rc;
    int (*parser)(char *s, void *vp, void *dp);
    
    for (*ip = 1; *ip < argc && argv[*ip][0] == '-'; ++*ip) {
	char *vp = NULL;
 	

	
	if (argv[*ip][1] == '\0' || (argv[*ip][1] == '-' && argv[*ip][2] == '\0')) {
	    ++*ip;
	    return 0;
	}
	
	/* Long argument */
	if (argv[*ip][1] == '-') {
	    char *s;
	    int d = 1;
	    
	    vp = strchr(argv[*ip]+2, '=');
	    if (vp)
		*vp++ = '\0';

	    s = argv[*ip]+2;
	    if (strncmp(s, "no-", 3) == 0) {
		d = -1;
		s += 3;
	    }
	    
	    for (k = 0; strcmp(options[k].s, s) != 0; k++)
		;
	    if (!options[k].s) {
		fprintf(stderr, "%s: Error: %s: Invalid switch\n",
			argv[0], argv[*ip]);
		exit(EX_USAGE);
	    }

	    parser = options[k].p ? options[k].p : int_get;
	    if (vp && options[k].v)
		rc = parser(vp, options[k].v, &d);
	    else if (argv[*ip+1] && options[k].v && (rc = parser(argv[*ip+1], options[k].v, &d)) == 1) {
		++*ip;
	    } else
		rc = parser(NULL, options[k].v, &d);
	    
	    if (rc < 0) {
		if (vp) 
		    fprintf(stderr, "%s: Error: --%s=%s: Invalid value\n",
			    argv[0], options[k].s, vp);
		else 
		    fprintf(stderr, "%s: Error: --%s: Parse failure\n",
			    argv[0], options[k].s);
		exit(EX_USAGE);
	    }
	} else {
	    /* Short options */
	    for (j = 1; argv[*ip][j]; j++) {
		int d = 1;

		
		for (k = 0; options[k].s && (options[k].c != argv[*ip][j]); k++)
		    ;
		if (!options[k].s) {
		    fprintf(stderr, "%s: Error: -%c: Invalid switch\n",
			    argv[0], argv[*ip][j]);
		    exit(EX_USAGE);
		}

		parser = options[k].p ? options[k].p : int_get;
		if (argv[*ip][j+1] && options[k].v && (rc = parser(vp = argv[*ip]+j+1, options[k].v, &d)) == 1) {
		    break;
		} else if (argv[*ip+1] && options[k].v && (rc = parser(vp = argv[*ip+1], options[k].v, &d)) == 1) {
		    ++*ip;
		    break;
		} else
		    rc = parser(vp = NULL, options[k].v, &d);
		
		if (rc < 0) {
		    if (vp) 
			fprintf(stderr, "%s: Error: -%c: Invalid value\n",
				argv[0], argv[*ip][j]);
		    else 
			fprintf(stderr, "%s: Error: -%c: Parse failure\n",
				argv[0], argv[*ip][j]);
		    exit(EX_USAGE);
		} 
	    }
	}
    }

    return 0;
}
