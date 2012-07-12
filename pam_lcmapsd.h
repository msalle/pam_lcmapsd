#ifndef _PAM_LCMAPSD_H
#define _PAM_LCMAPSD_H

#include "lcmapsd_client.h"

/************************************************************************/
/* DEFINES AND TYPES                                                    */
/************************************************************************/

/* Name of environment variable for the user */
#define PROXY_ENV_VAR	"X509_USER_PROXY"

/* Names used as 'module_data_name' to set data in pam_sm_authenticate and also
 * used for the internal environment */
#define PAM_PREFIX		"PAM_"
#define PAM_PROXY_FILENAME	PAM_PREFIX "X509_USER_PROXY"
#define PAM_DN			PAM_PREFIX "DN"
#define PAM_NFQAN		PAM_PREFIX "NFQAN"
#define PAM_FQANS		PAM_PREFIX "FQANS"
#define PAM_TARGET_UID		PAM_PREFIX "TARGET_UID"
#define PAM_TARGET_GID		PAM_PREFIX "TARGET_GID"
#define PAM_TARGET_NSGID	PAM_PREFIX "TARGET_NSGID"
#define PAM_TARGET_SGIDS	PAM_PREFIX "TARGET_SGIDS"

/* LCMAPSd defaults */
#define DEF_URL		    "https://localhost:8443/lcmaps/mapping/ssl"
#define DEF_MODE	    LCMAPSD_MODE_FULLSSL
#define DEF_TIMEOUT	    1L
#define DEF_FORMAT	    "/tmp/x509up_u%d.XXXXXX"    /* formatstring for file
							 */
#define DEF_RENAME	    1   /* rename (copy and remove) existing file */
#define DEF_CHOWN	    1   /* chown existing file */
#define DEF_RMPROXYFAIL	    0   /* remove proxy on failure */
#define DEF_PROXYASCAFILE   0	/* also set proxy as cafile, necessary on RH6 */
#define DEF_USEENV	    1	/* use pam environment to work around pam data
				 */

/* Config file/cmdline option fields */
#define OPT_CONFIG		"config"
#define OPT_CAPATH		"capath"
#define OPT_CAFILE		"cafile"
#define OPT_HOSTCERT		"hostcert"
#define OPT_HOSTKEY		"hostkey"
#define OPT_LCMAPSDURL		"lcmapsd_url"
#define OPT_LCMAPSDTIMEOUT	"lcmapsd_timeout"
#define OPT_LCMAPSDMODE		"lcmapsd_mode"
#define OPT_PROXYFMT		"proxyfmt"
#define OPT_RENAME		"rename"
#define OPT_CHOWN		"chown"
#define OPT_RMPROXYFAIL		"del_proxy_on_fail"
#define OPT_PROXYASCAFILE	"proxy_as_cafile"
#define OPT_USEENV		"intern_env"

/* Structure containing all the options for pam module */
typedef struct {
    char *conffile;	    /* Name of config file */

    lcmapsd_opts_t lcmapsd; /* Connection options */

    char *proxyfmt;	    /* Format string for proxy file */
    int rename;		    /* Whether to rename into standard form */
    int chown;		    /* Whether to chown to target user */
    int rmproxyfail;	    /* Whether to remove proxy upon failure */
    int proxyascafile;	    /* Whether to set proxy also as cafile */
    int useenv;		    /* use pam environment to work around pam data */
} pam_lcmapsd_opts_t;

/* Enum with all typical return values, to be mapped on proper pam-function
 * return values */
typedef enum {
    MYPAM_SUCCESS	= 0,	/* success */
    MYPAM_ERROR		= 1,	/* system error */
    MYPAM_DATA_MISSING	= 2,	/* missing pam data */
    MYPAM_USER_UNKNOWN	= 3,	/* username unknown */
    MYPAM_CRED_EXPIRED	= 4,	/* credential expired */
    MYPAM_AUTH_ERR	= 5,	/* credential invalid */
} mypam_err_t;

/************************************************************************/
/* FUNCTION PROTOTYPES                                                  */
/************************************************************************/

/**
 * Initializes the options structure
 * \param opts configuration options structure 
 */
void _pam_lcmapsd_config_init(pam_lcmapsd_opts_t *opts);

/**
 * free()s all memory contained in opts structure
 * \param opts struct containing the configuration options
 */
void _pam_lcmapsd_config_free(pam_lcmapsd_opts_t *opts);

/**
 * Parses the config file in opts.conffile, and leaves the output in the
 * different opts fields. When an option is unset the value is left unchanged.
 * \param opts struct containing the configuration options
 * \return -1 I/O error
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   0 success
 */
int _pam_lcmapsd_parse_config(pam_lcmapsd_opts_t *opts);

/**
 * Parses the commandline options (incl config if present), and leaves the
 * output in the different opts fields
 * \param argc pam argc
 * \param argv pam argv
 * \param opts struct containing the configuration options
 * \return -1 I/O error (from config file)
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   >0 index+1 of wrong commandline option
 *	   0 success
 */
int _pam_lcmapsd_parse_cmdline(int argc, const char *argv[], 
				pam_lcmapsd_opts_t *opts);

#endif
