#include <security/pam_modules.h>

#include <security/pam_ext.h>	/* For pam_syslog */
#include <syslog.h>

#include <stdio.h>  /* NULL */
#include <stdlib.h>  /* free() */
#include <string.h> /* strdup() */
#include <sys/types.h>	/* stat() */
#include <sys/stat.h>	/* stat() */
#include <unistd.h>	/* stat() and unlink() */ 
#include <errno.h>

#include "pam_lcmapsd.h"

/************************************************************************/
/* DEFINES                                                              */
/************************************************************************/

/* authentication part: need pam_sm_authenticate and pam_sm_setcred */
#define PAM_SM_AUTH

/* account part: need pam_sm_account */
#define PAM_SM_ACCOUNT

/* session part: need pam_sm_open_session and pam_sm_close_session */
#define PAM_SM_SESSION

/************************************************************************/
/* PRIVATE FUNCTIONS                                                    */
/************************************************************************/

/**
 * Cleanup function for string data, needed by pam_set_data
 * \param pamh pam handle
 * \param data string data
 * \param error_status see pam_set_data
 */
static void _pam_string_cleanup(pam_handle_t *pamh, void *data,
				   int error_status)	{
    if (data)
	free(data);
}

/**
 * Input credential retrieval function for proxy.
 *
 * Obtains name of proxyfile from 1) pam data or 2) getenv(PROXY_ENV_VAR) or 3)
 * pam_getenv(PROXY_ENV_VAR). Upon success the name will strdup-ped into
 * proxyfile.
 * \param pamh pam handle
 * \param cred credential structure, which will contain proxy filename upon
 * success or be unchanged otherwise
 * \return MYPAM_SUCCESS upon succes, or suitable mypam_err_t error.
 */
static mypam_err_t _get_proxy(pam_handle_t *pamh, cred_t *cred)  {
    int rc;
    const char *proxy=NULL;

    /* Need to have credentials */
    /* try pam data first */
    rc=pam_get_data(pamh, PAM_PROXY_FILENAME, (const void **)&proxy);
    if (rc==PAM_NO_MODULE_DATA) {
	/* no data, try env */
	if ( (proxy=getenv(PROXY_ENV_VAR))==NULL)   {
	    /* no env, try pam_env */
	    if ( (proxy=pam_getenv(pamh, PROXY_ENV_VAR))==NULL )    {
		pam_syslog(pamh, LOG_ERR, "No proxy found, cannot continue\n");
		return MYPAM_DATA_MISSING;
	    }
	}
    } else if (rc!=PAM_SUCCESS)	{
	pam_syslog(pamh,LOG_ERR,"Error obtaining data: %s\n",
		pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    }

    pam_syslog(pamh,LOG_DEBUG,"Found proxy in %s\n", proxy);

    /* Now set proxyfile */
    free(cred->proxyfile);
    if ( (cred->proxyfile=strdup(proxy))==NULL) {
	pam_syslog(pamh, LOG_ERR, "Out of memory\n");
	return MYPAM_ERROR;
    }
    return MYPAM_SUCCESS;
}

/**
 * Input credential retrieval function for DN/FQANs.
 *
 * Obtains DN pam data or PAM_USER item and optionally FQANs from pam data. Upon
 * success it will be strdupped into the credential data.
 * \param pamh pam handle
 * \param cred will contain DN and FQANs upon success or be unchanged otherwise
 * \return PAM_SUCCESS upon success (at least DN), or appropriate
 * mypam_err_t error.
 */
static mypam_err_t _get_dn_fqans(pam_handle_t *pamh,cred_t *cred)	{
    int rc,i;
    const char *dn_buf=NULL;
    int *nfqan_buf=NULL;
    const char **fqans_buf=NULL;

    /* DN */
    rc=pam_get_data(pamh, PAM_DN, (const void **)&dn_buf);
    if (rc==PAM_NO_MODULE_DATA)	{
	/* If unset, try PAM_USER item */
	rc=pam_get_item(pamh, PAM_USER, (const void **)&dn_buf);
	if (rc!=PAM_SUCCESS)	{
	    pam_syslog(pamh, LOG_ERR, "No DN found, cannot continue\n");
	    return MYPAM_DATA_MISSING;
	}
    }
    /* Check it's non-zero */
    if (rc!=PAM_SUCCESS || dn_buf==NULL )	{
	pam_syslog(pamh,LOG_ERR,"Error obtaining data: %s\n",
		pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    }
    if ( (cred->DN=strdup(dn_buf))==NULL )  {
	pam_syslog(pamh, LOG_ERR, "Out of memory\n");
	return MYPAM_ERROR;
    }
    
    /* NFQAN */
    rc=pam_get_data(pamh, PAM_NFQAN, (const void **)&nfqan_buf);
    if (rc==PAM_NO_MODULE_DATA)	{ /* not necessary: no error */
	pam_syslog(pamh, LOG_DEBUG, "No FQANs found\n");
	return MYPAM_SUCCESS;
    } else if (rc!=PAM_SUCCESS)	{
	pam_syslog(pamh,LOG_ERR,"Error obtaining data: %s\n",
		pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    }
    cred->nfqan=*nfqan_buf;

    /* NFQAN exists, then FQANS must exist*/
    rc=pam_get_data(pamh, PAM_FQANS, (const void **)&fqans_buf);
    if (rc==PAM_NO_MODULE_DATA)	{
	pam_syslog(pamh, LOG_ERR,
		"No FQANs found although PAM_NFQAN is set (=%d)\n",cred->nfqan);
	return MYPAM_ERROR;
    } else if (rc!=PAM_SUCCESS)	{
	pam_syslog(pamh,LOG_ERR,"Error obtaining data: %s\n",
		pam_strerror(pamh,rc));
	return MYPAM_ERROR;
    }
    /* Retrieve FQANs */
    if (cred->nfqan > 0)    {
	if ( (cred->FQAN=calloc(cred->nfqan,sizeof(char *)))==NULL )	{
	    pam_syslog(pamh, LOG_ERR, "Out of memory\n");
	    return MYPAM_ERROR;
	}
	for (i=0; i<cred->nfqan; i++)	{
	    if ( (cred->FQAN[i]=strdup(fqans_buf[i]))==NULL)	{
		pam_syslog(pamh, LOG_ERR, "Out of memory\n");
		return MYPAM_ERROR;
	    }
	}
    }

    return MYPAM_SUCCESS;
}

/**
 * Output-credential to pam-data function.
 *
 * Stores LCMAPS target user credential data (uid, gid, sgids) into pam data.
 * \param pamh pam handle
 * \param cred credential structure used for target uid/gid.
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _store_cred(pam_handle_t *pamh, cred_t *cred)  {
    int rc,i;
    uid_t *uid_buf=NULL;
    gid_t *gid_buf=NULL,*sgid_buf=NULL;
    int *nsgid_buf=NULL;

    /* malloc data buffers */
    if ( (uid_buf=malloc(sizeof(uid_t)))==NULL ||
	 (gid_buf=malloc(sizeof(gid_t)))==NULL ||
	 (nsgid_buf=malloc(sizeof(int)))==NULL ||
	 (cred->nsgid>0 && (sgid_buf=calloc(cred->nsgid,sizeof(gid_t)))==NULL))
    {
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	return MYPAM_ERROR;
    }

    /* Store credentials in buffers */
    *uid_buf=cred->uid;
    *gid_buf=cred->gid;
    *nsgid_buf=cred->nsgid;
    for (i=0; i<(cred->nsgid); i++)
	sgid_buf[i]=cred->sgids[i];

    /* Store uid in pam data */
    if ( (rc=pam_set_data(pamh, PAM_TARGET_UID, uid_buf, _pam_string_cleanup))
	    !=PAM_SUCCESS)    {
	pam_syslog(pamh,LOG_ERR,"Cannot store uid as pam data: %s\n",
		pam_strerror(pamh,rc));
	free(uid_buf);
	free(gid_buf);
	return MYPAM_ERROR;
    }

    /* Store gid in pam data */
    if ( (rc=pam_set_data(pamh, PAM_TARGET_GID, gid_buf, _pam_string_cleanup))
	    !=PAM_SUCCESS)    {
	pam_syslog(pamh,LOG_ERR,"Cannot store gid as pam data: %s\n",
		pam_strerror(pamh,rc));
	free(gid_buf);
	return MYPAM_ERROR;
    }

    /* Store sgids in pam data */
    if ( (rc=pam_set_data(pamh, PAM_TARGET_NSGID, nsgid_buf,
		    _pam_string_cleanup))!=PAM_SUCCESS ||
	 (rc=pam_set_data(pamh, PAM_TARGET_SGIDS, sgid_buf,
		    _pam_string_cleanup))!=PAM_SUCCESS )    {
	pam_syslog(pamh,LOG_ERR,"Cannot store sgids as pam data: %s\n",
		pam_strerror(pamh,rc));
	free(nsgid_buf);
	free(sgid_buf);
	return MYPAM_ERROR;
    }

    return MYPAM_SUCCESS;
}

/**
 * Output-credential from pam-data function.
 *
 * Retrieves credential data (proxyfile, target uid and gid) from the pam data
 * \param pamh pam handle
 * \param cred credential structure
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _retrieve_cred(pam_handle_t *pamh, cred_t *cred)  {
    int rc;
    const char *proxy_buf;
    uid_t *uid_buf;
    gid_t *gid_buf;

    /* proxy */
    /* Obtain from data */
    if ( (rc=pam_get_data(pamh,PAM_PROXY_FILENAME,(const void **)&proxy_buf))
		    !=PAM_SUCCESS) {
	    pam_syslog(pamh,LOG_ERR,"Cannot obtain proxy data: %s\n",
		    pam_strerror(pamh,rc));
	    return MYPAM_DATA_MISSING;
    }
    /* Put in credentials */
    if ( (cred->proxyfile=strdup(proxy_buf))==NULL )	{
	pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	return MYPAM_DATA_MISSING;
    }

    /* uid */
    /* Obtain from data */
    if ( (rc=pam_get_data(pamh,PAM_TARGET_UID,
		    (const void **)&(uid_buf)))!=PAM_SUCCESS) {
	    pam_syslog(pamh,LOG_ERR,"Cannot obtain uid data: %s\n",
		    pam_strerror(pamh,rc));
	    return MYPAM_DATA_MISSING;
    }
    /* Put in credentials */
    cred->uid=*uid_buf;

    /* gid */
    /* Obtain from data */
    if ( (rc=pam_get_data(pamh,PAM_TARGET_GID,
		    (const void **)&(gid_buf)))!=PAM_SUCCESS) {
	    pam_syslog(pamh,LOG_ERR,"Cannot obtain gid data: %s\n",
		    pam_strerror(pamh,rc));
	    return MYPAM_DATA_MISSING;
    }
    /* Put in credentials */
    cred->gid=*gid_buf;

    return MYPAM_SUCCESS;
}

/**
 * Output-credential pam-data to environment function.
 *
 * Stores the uid/gid and proxy filename pam data into the internal pam
 * environment for recovery by the _restore_pam_data function.
 * \param pamh pam handle
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _store_pam_data(pam_handle_t *pamh)	{
    const char *proxy_buf;
    uid_t *uid_buf;
    gid_t *gid_buf;
    char *buffer=NULL;
    int rc,len;

    /* proxy */
    rc=pam_get_data(pamh, PAM_PROXY_FILENAME, (const void **)&proxy_buf);
    if (rc==PAM_SUCCESS)    { /* data found */
	len=1+snprintf(buffer,0,"%s=%s",PAM_PROXY_FILENAME,proxy_buf);
	if ( (buffer=malloc(len))==NULL )
	    return MYPAM_ERROR;
	snprintf(buffer,len,"%s=%s",PAM_PROXY_FILENAME,proxy_buf);
	rc=pam_putenv(pamh,buffer);
	free(buffer);
	if (rc!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else if (rc==PAM_NO_MODULE_DATA)	{ /* clear env variable */
	if (pam_putenv(pamh,PAM_PROXY_FILENAME)!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else /* Error */
	return MYPAM_ERROR;

    /* uid */
    rc=pam_get_data(pamh, PAM_TARGET_UID, (const void **)&uid_buf);
    if (rc==PAM_SUCCESS)    { /* data found */
	len=1+snprintf(buffer,0,"%s=%d",PAM_TARGET_UID,*uid_buf);
	if ( (buffer=malloc(len))==NULL )
	    return MYPAM_ERROR;
	snprintf(buffer,len,"%s=%d",PAM_TARGET_UID,*uid_buf);
	rc=pam_putenv(pamh,buffer);
	free(buffer);
	if (rc!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else if (rc==PAM_NO_MODULE_DATA)	{ /* clear env variable */
	if (pam_putenv(pamh,PAM_TARGET_UID)!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else /* Error */
	return MYPAM_ERROR;

    /* gid */
    rc=pam_get_data(pamh, PAM_TARGET_GID, (const void **)&gid_buf);
    if (rc==PAM_SUCCESS)    {
	len=1+snprintf(buffer,0,"%s=%d",PAM_TARGET_GID,*gid_buf);
	if ( (buffer=malloc(len))==NULL )
	    return MYPAM_ERROR;
	snprintf(buffer,len,"%s=%d",PAM_TARGET_GID,*gid_buf);
	rc=pam_putenv(pamh,buffer);
	free(buffer);
	if ( rc!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else if (rc==PAM_NO_MODULE_DATA)	{ /* clear env variable */
	if (pam_putenv(pamh,PAM_TARGET_GID)!=PAM_SUCCESS)
	    return MYPAM_ERROR;
    } else
	return MYPAM_ERROR;

    return MYPAM_SUCCESS;
}

/**
 * Output-credential pam-data from environment function.
 *
 * Restores proxy filename, uid and gid from the internal environment, and
 * stores it in the pam data. \See _store_pam_data
 * \param pamh pam handle
 * \return MYPAM_SUCCESS upon success or a suitable mypam_err_t error.
 */
static mypam_err_t _restore_pam_data(pam_handle_t *pamh)	{
    const char *envval;
    char *proxy_buf;
    uid_t *uid_buf;
    gid_t *gid_buf;
    int rc;

    /* proxy */
    if ( (envval=pam_getenv(pamh, PAM_PROXY_FILENAME)) != NULL )    {
	/* Copy for data */
	if ( (proxy_buf=strdup(envval))==NULL)	{
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return MYPAM_ERROR;
	}
	/* Store in data */
	if ( (rc=pam_set_data(pamh,PAM_PROXY_FILENAME,
			  proxy_buf,_pam_string_cleanup))!=PAM_SUCCESS )    {
	    pam_syslog(pamh,LOG_ERR,"Cannot put %s in pam data: %s\n",
		proxy_buf,pam_strerror(pamh,rc));
	    free(proxy_buf);
	    return MYPAM_ERROR;
	}
	/* Remove from env */
	if ( (rc=pam_putenv(pamh,PAM_PROXY_FILENAME))!=PAM_SUCCESS )  {
	    pam_syslog(pamh,LOG_ERR,"Cannot remove %s from pam env: %s\n",
		PAM_PROXY_FILENAME,pam_strerror(pamh,rc));
	    return MYPAM_ERROR;
	}
    }

    /* uid */
    if ( (envval=pam_getenv(pamh, PAM_TARGET_UID)) != NULL )    {
	/* Copy for data */
	if ( (uid_buf=malloc(sizeof(uid_t)))==NULL )	{
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return MYPAM_ERROR;
	}
	/* Read out envval */
	if ( sscanf(envval,"%d",uid_buf)!=1)   {
	    pam_syslog(pamh,LOG_ERR,"Cannot get uid from %s\n",envval);
	    free(uid_buf);
	    return MYPAM_ERROR;
	}
	/* Store in data */
	if ( (rc=pam_set_data(pamh,PAM_TARGET_UID,
			  uid_buf,_pam_string_cleanup))!=PAM_SUCCESS )    {
	    pam_syslog(pamh,LOG_ERR,"Cannot put %d in pam data: %s\n",
		*uid_buf,pam_strerror(pamh,rc));
	    free(uid_buf);
	    return MYPAM_ERROR;
	}
	/* Remove from env */
	if ( (rc=pam_putenv(pamh,PAM_TARGET_UID))!=PAM_SUCCESS )  {
	    pam_syslog(pamh,LOG_ERR,"Cannot remove %s from pam env: %s\n",
		PAM_TARGET_UID,pam_strerror(pamh,rc));
	    return MYPAM_ERROR;
	}
    }

    /* gid */
    if ( (envval=pam_getenv(pamh, PAM_TARGET_GID)) != NULL )    {
	/* Copy for data */
	if ( (gid_buf=malloc(sizeof(gid_t)))==NULL )	{
	    pam_syslog(pamh,LOG_ERR,"Out of memory\n");
	    return MYPAM_ERROR;
	}
	/* Read out envval */
	if ( sscanf(envval,"%d",gid_buf)!=1)   {
	    pam_syslog(pamh,LOG_ERR,"Cannot get gid from %s\n",envval);
	    free(gid_buf);
	    return MYPAM_ERROR;
	}
	/* Store in data */
	if ( (rc=pam_set_data(pamh,PAM_TARGET_GID,
			  gid_buf,_pam_string_cleanup))!=PAM_SUCCESS )    {
	    pam_syslog(pamh,LOG_ERR,"Cannot put %d in pam data: %s\n",
		*gid_buf,pam_strerror(pamh,rc));
	    free(gid_buf);
	    return MYPAM_ERROR;
	}
	/* Remove from env */
	if ( (rc=pam_putenv(pamh,PAM_TARGET_GID))!=PAM_SUCCESS )  {
	    pam_syslog(pamh,LOG_ERR,"Cannot remove %s from pam env: %s\n",
		PAM_TARGET_GID,pam_strerror(pamh,rc));
	    return MYPAM_ERROR;
	}
    }

    return MYPAM_SUCCESS;
}

/**
 * Proxy chowning and renaming
 *
 * Rename and/or chowns the proxy using the given options and credentials.
 * \param pamh pam handle
 * \param opts options incl format of proxy filename
 * \param cred credentials incl. target uid and gid and proxy filename
 * \return MYPAM_SUCCESS on success or a suitable error code
 */
static int _chown_rename_proxy(pam_handle_t *pamh,
			       pam_lcmapsd_opts_t *opts, cred_t *cred)  {
    int rc,err,len;
    lcmapsd_err_t lrc;
    char *buffer=NULL;
    int prc=PAM_SUCCESS;

    /* Chown */
    if (opts->chown && _lcmapsd_chown(cred, &err) !=LCMAPSD_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "Chowning proxy failed: %s\n",strerror(err));
	return MYPAM_ERROR;
    }

    /* Rename */
    if (opts->rename)	{
	lrc=_lcmapsd_rename(cred, opts->proxyfmt, &err);
	switch (lrc)	{
	    case LCMAPSD_NO_ACTION:
		/* Nothing to do */
		prc=MYPAM_SUCCESS;
		break;
	    case LCMAPSD_SUCCESS:
		/* Make duplicate for pam data */
		if ( (buffer=strdup(cred->proxyfile))==NULL)    {
		    pam_syslog(pamh, LOG_ERR, "Out of memory\n");
		    break;
		}
		/* Store pam data */
		if ( (rc=pam_set_data(pamh,PAM_PROXY_FILENAME,
					   (void *)buffer,
					   _pam_string_cleanup))!=PAM_SUCCESS) {
		    pam_syslog(pamh,LOG_ERR,
			    "Cannot set data for proxy %s: %s\n",
			    cred->proxyfile,pam_strerror(pamh,rc));
		    free(buffer);
		    break;
		}

		/* proxy is present as data, now set it in the pam environment
		 * for the user */
		len=2+strlen(PROXY_ENV_VAR)+strlen(cred->proxyfile);
		if ( (buffer=(char *)malloc(len))==NULL )	{
		    pam_syslog(pamh, LOG_ERR, "Out of memory\n");
		    break;
		}
		snprintf(buffer,len,"%s=%s",PROXY_ENV_VAR,cred->proxyfile);
		/* Put var in env */
		if ( (rc=pam_putenv(pamh, buffer))!=PAM_SUCCESS )   {
		    pam_syslog(pamh,LOG_ERR,
			    "Cannot set data for proxy %s: %s\n",
			    cred->proxyfile,pam_strerror(pamh,rc));
		    free(buffer);
		    break;
		}
		prc=MYPAM_SUCCESS;
		break;
	    case LCMAPSD_OUT_OF_MEM:
		pam_syslog(pamh, LOG_ERR, "Out of memory\n");
		prc=MYPAM_ERROR;
		break;
	    case LCMAPSD_RENAME_ERR:
		pam_syslog(pamh, LOG_ERR, "Renaming proxy failed: %s\n",
			strerror(err));
		prc=MYPAM_ERROR;
		break;
	    default:
		pam_syslog(pamh, LOG_ERR, "Unexpected error code %d\n", lrc);
		prc=MYPAM_ERROR;
		break;
	}
    }
    return prc;
}

/**
 * Proxy removal
 *
 * Removes proxy in cred (when set) from disk. Upon error errno is returned in
 * *err
 * \param pamh pam handle
 * \param cred credential structure containing proxy filename
 * \param *err will contain errno upon error
 * \return 0 on success (or proxyfile==NULL), -1 on error
 */
static int _remove_proxy(pam_handle_t *pamh, cred_t *cred, int *err)    {
    /* If we don't know the proxy name, we can't do anything */
    if (cred->proxyfile==NULL)
	return 0;

    /* Remove the file */
    if (unlink(cred->proxyfile)==-1)	{
	pam_syslog(pamh,LOG_WARNING,"Could not remove proxy file %s\n",
		cred->proxyfile);
	*err=errno;
	return -1;
    }
    pam_syslog(pamh,LOG_INFO,"Removed proxy file %s\n", cred->proxyfile);

    return 0;
}

/**
 * cmdline option parsing log function
 *
 * Parses return value from _pam_lcmapsd_parse_cmdline() and logs corresponding
 * error message
 * \param pamh pam handle
 * \param rc return code from _pam_lcmapsd_parse_cmdline
 * \param argv pam_sm_authenticate argv
 * \param opts configure options
 */
static void _parse_opts_cmdline_returncode(pam_handle_t *pamh,
					   int rc, const char *argv[],
					   pam_lcmapsd_opts_t *opts)	{
    switch(rc)  {
	case -1:
	    pam_syslog(pamh, LOG_ERR,
		"I/O Error while parsing config file (%s)\n",opts->conffile);
	    break;
	case -2:
	    pam_syslog(pamh, LOG_ERR,
		"Permission of config file are wrong (%s)\n",opts->conffile);
	    break;
	case -3:
	    pam_syslog(pamh, LOG_ERR,
		"Out of memory while parsing options\n");
	    break;
	default:
	    pam_syslog(pamh, LOG_ERR,
		"Syntax error around option %s\n",argv[rc-1]);
	    break;
    }
}

/**
 * LCMAPSd interaction parsing function
 *
 * Parses error code returned by _lcmapsd_curl and logs a pam syslog message
 * \param pamh pam handle
 * \param rc return code from _lcmapsd_curl
 * \param errstr contains curl error message and will be freed
 * \return MYPAM_SUCCESS on LCMAPSD_SUCCESS or a suitable error on failure
 */
static int _parse_lcmapsd_returncode(pam_handle_t *pamh,
                                     lcmapsd_err_t rc, char *errstr) {
    /* Default pam return code:  */
    int prc=MYPAM_ERROR;

    switch(rc)  {
	case LCMAPSD_SUCCESS:
	    prc=MYPAM_SUCCESS;
	    break;
	case LCMAPSD_URL_UNKNOWN:
	    pam_syslog(pamh,LOG_ERR,"LCMAPSD URL is invalid\n");
	    break;
	case LCMAPSD_MISSING_CRED:
	    prc=MYPAM_DATA_MISSING;
	    pam_syslog(pamh,LOG_ERR,"User credentials are unset\n");
	    break;
	case LCMAPSD_EXPIRED_CRED:
	    prc=MYPAM_CRED_EXPIRED;
	    pam_syslog(pamh,LOG_ERR,"User credentials have expired\n");
	    break;
	case LCMAPSD_OUT_OF_MEM:
	    pam_syslog(pamh,LOG_ERR,"Out of memory while connecting to LCMAPSd\n");
	    break;
	case LCMAPSD_PARSE_ERR:
	    pam_syslog(pamh,LOG_ERR,"Cannot parse output of LCMAPSd\n");
	    break;
	case LCMAPSD_FORBIDDEN:
	    prc=MYPAM_AUTH_ERR;
	    pam_syslog(pamh,LOG_ERR,"LCMAPSd replied forbidden (403)\n");
	    break;
	case LCMAPSD_CURL_ERR:
	    if (errstr)
		pam_syslog(pamh,LOG_ERR,"Error in LCMAPSd interaction: %s\n",
			errstr);
	    else
		pam_syslog(pamh,LOG_ERR,"Error in LCMAPSd interaction\n");
	    break;
	case LCMAPSD_RESPONSE_ERR:
	    pam_syslog(pamh,LOG_ERR,"Error in LCMAPSd response\n");
	    break;
	default:
	    pam_syslog(pamh,LOG_ERR,"Unexpected error code %d\n",rc);
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
 * authentication/authorization function
 *
 * Implements authentication/authorization using the restful LCMAPSD from either
 * a proxyfile or DN+FQANs. It stores the credentials in pam data (and
 * optionally in the internal pam environment). Used by either
 * pam_sm_authenticate or pam_sm_acct_mgmt
 * \param see pam_sm_authenticate or pam_sm_acct_mgmt
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error.
 */
static mypam_err_t _pam_auth(pam_handle_t *pamh,
			     int argc, const char **argv) {
    cred_t cred;
    pam_lcmapsd_opts_t opts;
    int rc,err=0;
    lcmapsd_err_t lrc;
    mypam_err_t prc;
    char *errstr=NULL;

    /* Initialize cred structure */
    _lcmapsd_init_cred(&cred);

    /* Initialize opts */
    _pam_lcmapsd_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_lcmapsd_parse_cmdline(argc,argv,&opts)) != 0)	{
	_parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	prc=MYPAM_ERROR;
	goto _auth_cleanup;
    }

    /* obtain proxy location (when applicable) from data/env */
    if (opts.lcmapsd.mode==LCMAPSD_MODE_FULLSSL)   {
	if ( (prc=_get_proxy(pamh,&cred))!=MYPAM_SUCCESS)
	    goto _auth_cleanup;
	/* Put proxy location also in lcmaps credential fields */
	free(opts.lcmapsd.certinfo.clientcert);
	opts.lcmapsd.certinfo.clientcert=strdup(cred.proxyfile);
	free(opts.lcmapsd.certinfo.clientkey);
	opts.lcmapsd.certinfo.clientkey=strdup(cred.proxyfile);
	if (opts.proxyascafile)	{
	    free(opts.lcmapsd.certinfo.cafile);
	    opts.lcmapsd.certinfo.cafile=strdup(cred.proxyfile);
	}
    } else if (opts.lcmapsd.mode==LCMAPSD_MODE_BASIC)   {
	if ( (prc=_get_dn_fqans(pamh,&cred))!=MYPAM_SUCCESS)
	    goto _auth_cleanup;
    }

    /* Do lcmapsd run */
    lrc=_lcmapsd_curl(&(opts.lcmapsd), &cred, &errstr);

    /* Parse return code (this also free()s the errstr) */
    if ( (prc=_parse_lcmapsd_returncode(pamh, lrc, errstr)) != MYPAM_SUCCESS)
	goto _auth_cleanup;

    /* Store creds in pam data */
    if ( (prc=_store_cred(pamh, &cred)) != MYPAM_SUCCESS)
	goto _auth_cleanup;

    /* Optionally store pam data in internal env */
    if (opts.useenv)
	prc=_store_pam_data(pamh);

_auth_cleanup:
    /* On failure, remove proxy (when set in the options) */
    if (prc!=MYPAM_SUCCESS && opts.rmproxyfail)
	_remove_proxy(pamh,&cred,&err);

    /* Free cred struct */
    _lcmapsd_free_cred(&cred);

    /* Cleanup opts */
    _pam_lcmapsd_config_free(&opts);

    return prc;
}

/**
 * Credential setting function
 *
 * Implementing establishing the credentials obtained from an LCMAPS run. When
 * chown is set, it will chown the proxyfile to the target uid/gid, when rename
 * is set, it will rename the proxyfile according to the proxyfmt. When the
 * proxy filename has changed, the pam data will be updated and the
 * PROXY_ENV_VAR will be set to the new proxy filename. Used by either
 * pam_sm_setcred or pam_sm_open_session
 * \param see pam_sm_setcred or pam_sm_open_session
 * \return MYPAM_SUCCESS on success or a suitable mypam_err_t error.
 */
static mypam_err_t _pam_establish_cred(pam_handle_t *pamh,
			       int argc, const char **argv) {
    pam_lcmapsd_opts_t opts;
    cred_t cred;
    int rc,err=0;
    mypam_err_t prc;

    /* Initialize cred structure */
    _lcmapsd_init_cred(&cred);

    /* Initialize opts */
    _pam_lcmapsd_config_init(&opts);

    /* Get commandline (and perhaps config file) options */
    if ( (rc=_pam_lcmapsd_parse_cmdline(argc,argv,&opts)) !=0 ) {
        _parse_opts_cmdline_returncode(pamh,rc,argv,&opts);
	prc=MYPAM_ERROR;
	goto _setcred_cleanup;
    }

    /* Try to retrieve the data from the pam environment */
    if (opts.useenv)	{
	if ( (prc=_restore_pam_data(pamh))!=MYPAM_SUCCESS)
	    goto _setcred_cleanup;
    }

    /* Get pam data */
    if ( (prc=_retrieve_cred(pamh, &cred))!=MYPAM_SUCCESS)
	goto _setcred_cleanup;

    /* chown and rename proxy when set in opts, updata data and set env
     * variable. Do only for full mode. */
    if (opts.lcmapsd.mode==LCMAPSD_MODE_FULLSSL)
	prc=_chown_rename_proxy(pamh,&opts,&cred);

_setcred_cleanup:
    /* On failure, remove proxy (when set in the options) */
    if (prc!=MYPAM_SUCCESS && opts.rmproxyfail)
	_remove_proxy(pamh,&cred,&err);

    /* Free cred struct */
    _lcmapsd_free_cred(&cred);

    /* Cleanup opts */
    _pam_lcmapsd_config_free(&opts);

    /* all done */
    return prc;
}


/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * pam_sm_authenticate() function implementing the pam_authenticate function for
 * doing an LCMAPS run from either a proxyfile or DN+FQANs (see _pam_auth()). It
 * stores the credentials in pam data (and optionally in the internal pam
 * environment).
 * \param see pam_sm_authenticate
 * \return see pam_sm_authenticate
 */
PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_auth(pamh, argc, argv);

    switch (rc)	{
	case MYPAM_SUCCESS:
	    return PAM_SUCCESS;
	case MYPAM_USER_UNKNOWN:
	    return PAM_USER_UNKNOWN;
	case MYPAM_AUTH_ERR:
	    return PAM_AUTH_ERR;
	case MYPAM_ERROR:
	case MYPAM_DATA_MISSING:
	default:
	    return PAM_AUTHINFO_UNAVAIL;
    }
    
    /* MYPAM_CRED_EXPIRED cannot be logically mapped */
}

/**
 * pam_sm_acct_mgmt() function implementing the pam_acct_mgmt function for
 * doing an LCMAPS run from either a proxyfile or DN+FQANs (see _pam_auth()). It
 * stores the credentials in pam data (and optionally in the internal pam
 * environment).
 * \param see pam_sm_acct_mgmt
 * \return see pam_sm_acct_mgmt
 */
PAM_EXTERN int 
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_auth(pamh, argc, argv);

    switch (rc)	{
	case MYPAM_SUCCESS:
	    return PAM_SUCCESS;
	case MYPAM_USER_UNKNOWN:
	    return PAM_USER_UNKNOWN;
	case MYPAM_CRED_EXPIRED:
	    return PAM_NEW_AUTHTOK_REQD;
	case MYPAM_AUTH_ERR:
	    return PAM_AUTH_ERR;
	case MYPAM_ERROR:
	case MYPAM_DATA_MISSING:
	default:
	    /* Linux pam_acct_mgmt does not have a general failure */
	    return PAM_AUTH_ERR;
    }
}

/**
 * pam_sm_setcred() function implementing the pam_setcred function for doing an
 * LCMAPS run (see _pam_establish_cred()). When chown is set, it will chown the
 * proxyfile to the target uid/gid, when rename is set, it will rename the
 * proxyfile according to the proxyfmt. When the proxy filename has changed, the
 * pam data will be updated and the PROXY_ENV_VAR will be set to the new proxy
 * filename.
 * \param see pam_sm_setcred
 * \return see pam_sm_setcred
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    /* First handle credential removal: nothing to do */
    if ( flags & PAM_DELETE_CRED )
	return PAM_SUCCESS;

    rc=_pam_establish_cred(pamh, argc, argv);

    switch(rc)	{
	case MYPAM_SUCCESS:
	    return PAM_SUCCESS;
	case MYPAM_DATA_MISSING:
	    return PAM_CRED_UNAVAIL;
	case MYPAM_USER_UNKNOWN: /* Currently not used */
	    return PAM_USER_UNKNOWN;
	case MYPAM_CRED_EXPIRED: /* Currently not used */
	    return PAM_CRED_EXPIRED;
	case MYPAM_AUTH_ERR: /* Currently not used */ 
	case MYPAM_ERROR:
	default:
	    return PAM_CRED_ERR;
    }
}

/**
 * pam_sm_open_session() function implementing the pam_open_session function for
 * doing an LCMAPS run (see _pam_establish_cred()). When chown is set, it will
 * chown the proxyfile to the target uid/gid, when rename is set, it will rename
 * the proxyfile according to the proxyfmt. When the proxy filename has changed,
 * the pam data will be updated and the PROXY_ENV_VAR will be set to the new
 * proxy filename.
 * \param see pam_sm_open_session
 * \return see pam_sm_open_session
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    mypam_err_t rc;

    rc=_pam_establish_cred(pamh, argc, argv);

    switch(rc)	{
	case MYPAM_SUCCESS:
	    return PAM_SUCCESS;
	case MYPAM_DATA_MISSING:
	case MYPAM_USER_UNKNOWN: /* Currently not used */
	case MYPAM_CRED_EXPIRED: /* Currently not used */
	case MYPAM_AUTH_ERR: /* Currently not used */ 
	case MYPAM_ERROR:
	default:
	    return PAM_SESSION_ERR;
    }
}

/**
 * pam_sm_close_session() function implementing the pam_close_session function
 * for doing an LCMAPS run. Always successful.
 * \param see pam_sm_close_session
 * \return see pam_sm_close_session
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
