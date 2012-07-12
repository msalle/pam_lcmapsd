#ifndef _LCMAPSD_CLIENT_H
#define _LCMAPSD_CLIENT_H

#include <sys/types.h>

/************************************************************************/
/* DEFINES AND TYPEDEFS                                                 */
/************************************************************************/

/**
 * Struct used for setting the openssl certificate input files and directories
 */
typedef struct {
    char *capath;           /* OpenSSL CApath */
    char *cafile;           /* OpenSSL CAfile */
    char *clientcert;       /* client-side cert (e.g. hostcert) */
    char *clientkey;        /* client-side key */
} certinfo_t;

/**
 * Credential structure
 */
typedef struct {
    char *proxyfile;	    /* Proxy filename */
    char *DN;		    /* Distinguished name */
    char **FQAN;	    /* Fully Qualified Attribute Name */
    int nfqan;		    /* Number of FQANs */
    uid_t uid;		    /* target uid */
    gid_t gid;		    /* target primary gid */
    gid_t *sgids;	    /* target secondary gids */
    int nsgid;		    /* number of target secondary gids */
} cred_t;

/**
 * Type of LCMAPSd service interface
 */
typedef enum	{
    LCMAPSD_MODE_FULLSSL    = 1,    /* obtain input from client-side proxy */
    LCMAPSD_MODE_BASIC	    = 2,    /* obtain input from REST */
} lcmapsd_mode_t;

/**
 * LCMAPSd information structure */
typedef struct {
    certinfo_t certinfo;    /* CApath etc. */
    char *url;		    /* URL of LCMAPSd (incl. port) */
    long timeout;	    /* LCMAPSd timeout */
    lcmapsd_mode_t mode;    /* Full SSL or basic mode */
} lcmapsd_opts_t;

/**
 * Error codes for LCMAPSd interaction problems
 */
typedef enum    {
    LCMAPSD_SUCCESS		= 0,	/* ok */
    LCMAPSD_NO_ACTION		= 1,	/* nothing to do */
    LCMAPSD_URL_UNKNOWN		= 2,	/* lcmapsd url is invalid */ 
    LCMAPSD_MISSING_CRED	= 3,	/* no DN, ... */
    LCMAPSD_EXPIRED_CRED	= 4,	/* expired credentials */
    LCMAPSD_OUT_OF_MEM		= 5,	/* out of memory */
    LCMAPSD_PARSE_ERR		= 6,	/* response parse error */
    LCMAPSD_FORBIDDEN		= 7,	/* lcmapsd returned 403 */
    LCMAPSD_CURL_ERR		= 8,	/* curl interaction failed */
    LCMAPSD_RESPONSE_ERR	= 9,	/* did not obtain valid response */
    LCMAPSD_CHOWN_ERR		= 10,	/* could not chown proxy */
    LCMAPSD_RENAME_ERR		= 11,	/* could not rename proxy */
} lcmapsd_err_t;

/************************************************************************/
/* FUNCTION PROTOTYPES                                                  */
/************************************************************************/

/**
 * Initializes the credential structure
 * \param cred credential structure
 */
void _lcmapsd_init_cred(cred_t *cred);

/**
 * Free credential structure
 * \param cred credential structure
 */
void _lcmapsd_free_cred(cred_t *cred);

/**
 * Changes ownership of proxyfile to target uid and gid
 * \param cred credential structure
 * \err errno in case of error
 * \return LCMAPSD_SUCCESS on success or LCMAPSD_CHOWN_ERR on error
 */
lcmapsd_err_t _lcmapsd_chown(cred_t *cred, int *err);

/**
 * Renames proxyfile according to format
 * When fmt contains %d it is replace with the target uid, when it ends with
 * XXXXXX it is replaced by a random string using mkstemp(). Upon success, the
 * new proxyfile will be put in the credential structure.
 * \param cred credential structure
 * \param fmt filename format string
 * \err errno in case of error
 * \return LCMAPSD_SUCCESS on success or lcmapsd_err_t error string
 */
lcmapsd_err_t _lcmapsd_rename(cred_t *cred, const char *fmt, int *err);

/**
 * Calls out (via curl) to the LCMAPSd specified in opts, using the credentials
 * in cred. CURL errors may fill the errstr buffer which needs to be freed by
 * the caller. 
 * \param opts lcmapsd_opts_t containing the LCMAPSd configuration
 * \param cred contains the input (e.g. proxy) and output (uid, gid) credentials
 * \return LCMAPSD_SUCCESS or error
 */
lcmapsd_err_t _lcmapsd_curl(lcmapsd_opts_t *opts, cred_t *cred, char **errstr);

#endif
