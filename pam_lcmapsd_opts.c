#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pam_lcmapsd.h"

/************************************************************************/
/* PRIVATE FUNCTIONS                                                    */
/************************************************************************/

/**
 * Replaces dst with src iff src!=NULL, free-ing dst first.
 * \param dst destination
 * \param src source
 * \return dst (either old or new)
 */
static char *_subst_val(char **dst, char *src) {
    /* new value? */
    if (src!=NULL)  {
	if (*dst) free(*dst);
	*dst=src;
    }
    return *dst;
}

/**
 * Reads the config file into buffer
 * \param buffer will be malloced and contain the contents of the config file
 * \return 0 on success, -1 I/O failure, -2 permission failure, -3 memory
 * failure
 */
static int _read_conf_file(char **buffer, const char *conffile)   {
    char *buf;
    int rc=0,fd=0;
    struct stat fstatbuf;

    /* initialize buffer */
    buf=NULL;

    /* open file */
    if ( (fd=open(conffile, O_RDONLY))==-1 ||
	 fstat(fd, &fstatbuf) )
	return -1;  /* I/O error */

    /* basic checks. TODO: safeopen */
    if (!S_ISREG(fstatbuf.st_mode) ||	/* regular file? */
	fstatbuf.st_uid!=0 ||		/* root-owned? */
	(fstatbuf.st_mode & S_IWGRP) || /* unwriteable group? */
	(fstatbuf.st_mode & S_IWOTH))	{ /* unwriteable others? */
	rc=-2;
	goto conf_failed;
    }

    /* malloc buffer: filesize plus trailing \0 */
    if ( (buf=(char*)malloc(1+fstatbuf.st_size))==NULL )	{
	rc=-3;
	goto conf_failed;
    }

    /* Read config is filesize >0 */
    if (fstatbuf.st_size>0) {
	if ( read(fd, buf, fstatbuf.st_size)<=0 )	{
	    rc=-1;
	    goto conf_failed;
	}
    }
    /* Add trailing \0 */
    buf[fstatbuf.st_size]='\0';
    rc=0;
    close(fd);
    *buffer=buf;
    return rc;

conf_failed:
    if (buf)	free(buf);
    if (fd>0)	close(fd);

    return rc;
}

/**
 * Parses buf for option, which will be returned. Caller needs to free.
 * \param buf contains config file contents
 * \param option option name
 * \return value of option
 */
static char *_conf_value(const char *buf, const char *option)   {
    char *value=NULL;
    int optlen,pos=0,pos2,pos3,len;

    if (buf==NULL || option==NULL) return NULL;
    optlen=strlen(option);
    do {
	/* Find next non-whitespace */
	while (buf[pos]==' ' || buf[pos]=='\t' || buf[pos]=='\n')
	    pos++;

	if (buf[pos]=='\0')
	    return NULL;

	if (strncmp(&(buf[pos]),option,optlen)==0 &&
	    (buf[pos+optlen]==' ' || buf[pos+optlen]=='\t' ||
	     buf[pos+optlen]=='='))
	{   /* Found option */
	    /* Find start of value */
	    pos2=pos+optlen;
	    while ( buf[pos2]==' ' || buf[pos2]=='\t')
		pos2++;
	    if (buf[pos2]=='=') {
		do {
		    pos2++;
		} while (buf[pos2]==' ' || buf[pos2]=='\t');
	    }
	    /* Find end of value */
	    pos3=pos2;
	    while (buf[pos3]!='\n' && buf[pos3]!='\0' && buf[pos3]!='#')
		pos3++;
	    /* one back and remove trailing whitespace */
	    do {
		pos3--;
	    } while (buf[pos3]==' ' || buf[pos3]=='\t');
	    if ((len=pos3-pos2+1)>0)  {
		if ( (value=(char*)calloc(1,len+1))==NULL )
		    return NULL;
		strncpy(value,&(buf[pos2]),len);
		break;
	    }
	    pos=pos3;
	}
	/* Skip till next line or end of buffer */
	while (buf[pos]!='\n' && buf[pos]!='\0')
	    pos++;
    } while (value==NULL && buf[pos]!='\0');

    return value;
}

/**
 * Looks for option in buf, when successfully found, returns it value as string,
 * otherwise return default value
 * \param buf contains configuration
 * \param option option to look for
 * \param oldval current value, will be replaced if a new value is found
 * \return 1 when value is found, otherwise 0
 */
static int _conf_val_str(const char *buf, const char *option,
			 char **oldval) {
    char *value;
    int rc=0;

    if ( (value=_conf_value(buf, option)) != NULL ) {
	free(*oldval);
	*oldval=value;
	rc=1;
    }
    return rc;
}

/**
 * Looks for option in buf, when successfully found, returns it value converted
 * to long, otherwise default
 * \param buf contains configuration
 * \param option option to look for
 * \param oldval current value, will be replaced if a new value is found
 * \return 1 when new value is found, otherwise 0
 */
static int _conf_val_long(const char *buf, const char *option, long *oldval) {
    char *strval=NULL;
    long value;
    int rc=0;

    if ( (strval=_conf_value(buf, option))!=NULL &&
	 sscanf(strval,"%ld",&value)==1 ) {
	*oldval=value;
	rc=1;
    }
    free(strval);
    return rc;
}

/**
 * Looks for option in buf, when successfully found, oldval will be updated to
 * its value converted to int.
 * \param buf contains configuration
 * \param option option to look for
 * \param oldval current value, will be replaced if a new value is found
 * \return 1 when new value is found, otherwise 0
 */
static int _conf_val_int(const char *buf, const char *option, int *oldval) {
    char *strval=NULL;
    int value,rc=0;

    if ( (strval=_conf_value(buf, option))!=NULL &&
	 sscanf(strval,"%d",&value)==1 ) {
	*oldval=value;
	rc=1;
    }
    free(strval);
    return rc;
}

/**
 * Looks for option in buf, when successfully found, oldval will be updated to
 * its value converted to lcmapsd_mode_t.
 * \param buf contains configuration
 * \param option option to look for
 * \param oldval current value, will be replaced if a new value is found
 * \return 1 when new value is found, otherwise 0
 */
static int _conf_val_mode(const char *buf, const char *option,
			  lcmapsd_mode_t *oldval)   {
    char *strval=NULL;
    int rc=0;

    if ( (strval=_conf_value(buf, option))!=NULL) {
	if (strcmp(strval,"full")==0)	{
	    *oldval=LCMAPSD_MODE_FULLSSL;
	    rc=1;
	} else if (strcmp(strval,"basic")==0)	{
	    *oldval=LCMAPSD_MODE_BASIC;
	    rc=1;
	}
	free(strval);
    }
    return rc;
}

/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * Initializes the options structure
 * \param opts configuration options structure 
 */
void _pam_lcmapsd_config_init(pam_lcmapsd_opts_t *opts)	{
    opts->conffile=NULL;

    opts->lcmapsd.certinfo.cafile=opts->lcmapsd.certinfo.capath=
	opts->lcmapsd.certinfo.clientcert=opts->lcmapsd.certinfo.clientkey=NULL;

    opts->lcmapsd.url=strdup(DEF_URL);
    opts->lcmapsd.timeout=DEF_TIMEOUT;
    opts->lcmapsd.mode=DEF_MODE;

    opts->proxyfmt=strdup(DEF_FORMAT);
    opts->rename=DEF_RENAME;
    opts->chown=DEF_CHOWN;
    
    opts->useenv=DEF_USEENV;

}
/**
 * free()s all memory contained in opts structure
 * \param opts struct containing the configuration options
 */
void _pam_lcmapsd_config_free(pam_lcmapsd_opts_t *opts) {
    free(opts->conffile);
    opts->conffile=NULL;

    free(opts->lcmapsd.certinfo.capath);
    opts->lcmapsd.certinfo.capath=NULL;
    free(opts->lcmapsd.certinfo.cafile);
    opts->lcmapsd.certinfo.cafile=NULL;
    free(opts->lcmapsd.certinfo.clientcert);
    opts->lcmapsd.certinfo.clientcert=NULL;
    free(opts->lcmapsd.certinfo.clientkey);
    opts->lcmapsd.certinfo.clientkey=NULL;

    free(opts->lcmapsd.url);
    opts->lcmapsd.url=NULL;
    free(opts->proxyfmt);
    opts->proxyfmt=NULL;
}

/**
 * Parses the config file in opts.conffile, and leaves the output in the
 * different opts fields. When an option is unset the value is left unchanged. 
 * \param opts struct containing the configuration options
 * \return -1 I/O error
 *	   -2 permission error (of config file)
 *	   -3 memory error
 *	   0 success
 */
int _pam_lcmapsd_parse_config(pam_lcmapsd_opts_t *opts) {
    char *buf=NULL;
    int rc;

    if ( (rc=_read_conf_file(&buf, opts->conffile)) )
	goto finalize;

    _conf_val_str(buf, OPT_CAPATH,  &(opts->lcmapsd.certinfo.capath));
    _conf_val_str(buf, OPT_CAFILE,  &(opts->lcmapsd.certinfo.cafile));
    _conf_val_str(buf, OPT_HOSTCERT,&(opts->lcmapsd.certinfo.clientcert));
    _conf_val_str(buf, OPT_HOSTKEY, &(opts->lcmapsd.certinfo.clientkey));

    _conf_val_str(buf, OPT_LCMAPSDURL,    &(opts->lcmapsd.url));
    _conf_val_mode(buf,OPT_LCMAPSDMODE,   &(opts->lcmapsd.mode));
    _conf_val_long(buf,OPT_LCMAPSDTIMEOUT,&(opts->lcmapsd.timeout));

    _conf_val_str(buf,OPT_PROXYFMT,&(opts->proxyfmt));

    _conf_val_int(buf,OPT_RENAME,&(opts->rename));
    _conf_val_int(buf,OPT_CHOWN, &(opts->chown));
    _conf_val_int(buf,OPT_USEENV,&(opts->useenv));

finalize:
    free(buf);
    return rc;
}

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
				pam_lcmapsd_opts_t *opts) {
    int i,intval,rc;
    long longval;
    char *pos,*opt,*val;

    /* Note: pam opts start at 0, not at 1 */
    for (i=0; i<argc; i++)  {
	if ( (opt=strdup(argv[i])) == NULL )
	    return -3;
	/* Get value and remove from opt */
	if ( (pos=strchr(opt,'='))==NULL )  {
	    free(opt);
	    return i+1;
	}
	pos[0]='\0';
	/* strdup, since we need to free opt separately */
	if ( (val=strdup(&pos[1]))==NULL)   {
	    free(opt);
	    return -3;
	}

	/* Look for right option */
	if (strcmp(opt,OPT_CONFIG)==0)    {
	    _subst_val(&(opts->conffile),val);
	    if ( (rc=_pam_lcmapsd_parse_config(opts))!=0)   {
		free(opt);
		return rc;
	    }
	} else if (strcmp(opt,OPT_CAPATH)==0)
	    _subst_val(&(opts->lcmapsd.certinfo.capath),val);
	else if (strcmp(opt,OPT_CAFILE)==0)
	    _subst_val(&(opts->lcmapsd.certinfo.cafile),val);
	else if (strcmp(opt,OPT_HOSTCERT)==0)
	    _subst_val(&(opts->lcmapsd.certinfo.clientcert),val);
	else if (strcmp(opt,OPT_HOSTKEY)==0)
	    _subst_val(&(opts->lcmapsd.certinfo.clientkey),val);
	else if (strcmp(opt,OPT_LCMAPSDURL)==0)
	    _subst_val(&(opts->lcmapsd.url),val);
	else if (strcmp(opt,OPT_LCMAPSDMODE)==0)	{
	    if (strcmp(val,"full")==0)
		opts->lcmapsd.mode=LCMAPSD_MODE_FULLSSL;
	    else
		opts->lcmapsd.mode=LCMAPSD_MODE_BASIC;
	    free(val);
	} else if (strcmp(opt,OPT_LCMAPSDTIMEOUT)==0) {
	    if (sscanf(val,"%ld",&longval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->lcmapsd.timeout=longval;
	    free(val);
	} else if (strcmp(opt,OPT_PROXYFMT)==0)
	    _subst_val(&(opts->proxyfmt),val);
	else if (strcmp(opt,OPT_RENAME)==0)	{
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->rename=intval;
	    free(val);
	} else if (strcmp(opt,OPT_CHOWN)==0) {
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->chown=intval;
	    free(val);
	} else if (strcmp(opt,OPT_USEENV)==0)	{
	    if (sscanf(val,"%d",&intval)!=1)	{
		free(val); free(opt);
		return i+1;
	    }
	    opts->useenv=intval;
	    free(val);
	} else {
	    free(val); free(opt);
	    return i+1;
	}
	free(opt);
    }

    return 0;
}
