#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pam_lcmapsd.h"

/**
 * Parses error code returned by _lcmapsd_curl and logs a message on stderr
 * \param rc return code from _lcmapsd_curl
 * \param errstr contains curl error message and will be freed
 * \return 0 on LCMAPSD_SUCCESS or 1 on failure
 */
static int _parse_lcmapsd_returncode(int rc, char *errstr) {
    /* Default pam return code: 1 */
    int prc=1;

    switch(rc)  {
	case LCMAPSD_SUCCESS:
	    prc=0;
	    break;
	case LCMAPSD_URL_UNKNOWN:
	    fprintf(stderr,"LCMAPSD URL is invalid\n");
	    break;
	case LCMAPSD_MISSING_CRED:
	    fprintf(stderr,"User credentials are unset\n");
	    break;
	case LCMAPSD_OUT_OF_MEM:
	    fprintf(stderr,"Out of memory while connecting to LCMAPSd\n");
	    break;
	case LCMAPSD_PARSE_ERR:
	    fprintf(stderr,"Cannot parse output of LCMAPSd\n");
	    break;
	case LCMAPSD_FORBIDDEN:
	    fprintf(stderr,"LCMAPSd replied forbidden (403)\n");
	    break;
	case LCMAPSD_CURL_ERR:
	    if (errstr)
		fprintf(stderr,"Error in LCMAPSd interaction: %s\n", errstr);
	    else
		fprintf(stderr,"Error in LCMAPSd interaction\n");
	    break;
	    fprintf(stderr,"Error in LCMAPSd interaction: %s\n",errstr);
	    break;
	case LCMAPSD_RESPONSE_ERR:
	    fprintf(stderr,"Error in LCMAPSd response\n");
	    break;
	default:
	    fprintf(stderr,"Unexpected error code %d\n",rc);
	    break;
    }
    /* Free the errstr */
    if (errstr) {
        free(errstr);
        errstr=NULL;
    }

    return prc;
}

/**
 * Example lcmapsd client using the functions from lcmapsd_client
 */
int main(int argc, char *argv[])    {
    /* initialize cred structure */
    cred_t cred;
    pam_lcmapsd_opts_t opts;
    int rc,prc=0;
    int err;
    char *errstr=NULL;

    /* Initialize cred structure */
    _lcmapsd_init_cred(&cred);

    if (argc<2) {
        fprintf(stderr,"Usage: %s <proxy|DN> [conffile]\n",argv[0]);
        return 1;
    }

    /* Initialize opts */
    _pam_lcmapsd_config_init(&opts);

    /* Set conffile */
    opts.conffile=(argv[2] ? strdup(argv[2]) : strdup(PAM_LCMAPSD_CONF));
    if (opts.conffile==NULL)	{
	fprintf(stderr,"Out of memory\n");
	return 1;
    }

    /* Get commandline (and perhaps config file) options */
    switch(_pam_lcmapsd_parse_config(&opts))  {
	case 0:
	    break;
	case -1:
	    fprintf(stderr,
		"I/O Error while parsing config file (%s)\n",opts.conffile);
	    prc=1;
	    goto cleanup;
	case -2:
	    fprintf(stderr,
		"Permission of config file are wrong (%s)\n",opts.conffile);
	    prc=1;
	    goto cleanup;
	case -3:
	    fprintf(stderr,
		"Out of memory while parsing options\n");
	    prc=1;
	    goto cleanup;
	default:
	    fprintf(stderr,
		"Unknown error parsing the config file %s: %d\n",
		opts.conffile,rc);
	    prc=1;
	    goto cleanup;
    }

    /* Which mode ? */
    if (opts.lcmapsd.mode==LCMAPSD_MODE_FULLSSL)
	/* proxy location */
	cred.proxyfile=strdup(argv[1]);
    else
	/* user DN */
	cred.DN=strdup(argv[1]);

    /* Do lcmapsd run */
    rc=_lcmapsd_curl(&(opts.lcmapsd), &cred, &errstr);

    /* Parse return code (this also free-s clears the errstr) */
    if ( (prc=_parse_lcmapsd_returncode(rc,errstr))!=0 )
	goto cleanup;

    printf("Found credentials: uid=%d gid=%d\n",cred.uid,cred.gid);

    /* In full mode chown and/or rename proxy */
    if (opts.lcmapsd.mode==LCMAPSD_MODE_FULLSSL)    {
	/* Chown proxy */
	if (opts.chown && _lcmapsd_chown(&cred, &err) !=LCMAPSD_SUCCESS) {
	    fprintf(stderr,"Chowning proxy failed: %s\n",strerror(err));
	    prc=1;
	    goto cleanup;
	}

	/* Rename proxy */
	if (opts.rename)	{
	    rc=_lcmapsd_rename(&cred, opts.proxyfmt, &err);
	    switch (rc)	{
		case LCMAPSD_NO_ACTION:
		    /* Nothing to do */
		    prc=0;
		    break;
		case LCMAPSD_SUCCESS:
		    printf("Proxy now in %s\n",cred.proxyfile);
		    prc=0;
		    break;
		case LCMAPSD_OUT_OF_MEM:
		    fprintf(stderr,"Out of memory\n");
		    prc=1;
		    break;
		case LCMAPSD_RENAME_ERR:
		    fprintf(stderr,"Renaming proxy failed: %s\n",
			    strerror(err));
		    prc=1;
		    break;
		default:
		    fprintf(stderr,"Unexpected error code %d\n", rc);
		    prc=1;
		    break;
	    }
	}
    }

cleanup:
    /* Free credentials */
    _lcmapsd_free_cred(&cred);

    /* Cleanup opts */
    _pam_lcmapsd_config_free(&opts);

    return prc;
}

