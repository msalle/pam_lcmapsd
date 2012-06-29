#include <stdlib.h>	/* alloc fcies */
#include <string.h>	/* memcpy, strstr, strlen */
#include <unistd.h>	/* chown and fstat */
#include <sys/types.h>	/* fstat */
#include <sys/stat.h>	/* fstat */
#include <fcntl.h>	/* open */
#include <errno.h>

#include <curl/curl.h>

#include "lcmapsd_client.h"

/************************************************************************/
/* DEFINES AND TYPEDEFS                                                 */
/************************************************************************/

#define LCMAPSD_OUTPUT_FMT	"?format=json"

#define LCMAPSD_DN_PFX		"&subjectdn="

/* Used as buffer space by _curl_memwrite */
struct MemoryStruct {
    char *memory;
    size_t size;
};

/************************************************************************/
/* PRIVATE FUNCTIONS                                                    */
/************************************************************************/

/**
 * see cURL getinmemory.c example
 */
static size_t
_curl_memwrite(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
        return 0;

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/**
 * Parses memory as lcmapsd json. Looks for a valid uid.
 * \return 1 when uid/gid is found, otherwise 0
 */
static int _lcmapsd_parse_json(char *memory, cred_t *cred)    {
    char *pos0=memory,*pos=NULL;

    /* Find posix tag */
    if ( (pos0=strstr(pos0,"\"posix\""))==NULL ||
         (pos0=strstr(pos0,"{"))==NULL)
	return 0;

    /* uid */
    if ( (pos=strstr(pos0,"\"uid\""))==NULL ||
         (pos=strstr(pos,"{"))==NULL ||
         (pos=strstr(pos,"\"id\""))==NULL ||
         (pos=strstr(pos,":"))==NULL ||
         sscanf(pos+1,"%d",&(cred->uid))!=1)
	return 0;
	
    /* gid */
    if ( (pos=strstr(pos0,"\"pgid\""))==NULL ||
         (pos=strstr(pos,"{"))==NULL ||
         (pos=strstr(pos,"\"id\""))==NULL ||
         (pos=strstr(pos,":"))==NULL ||
         sscanf(pos+1,"%d",&(cred->gid))!=1)
	return 0;

    return 1;
}

/************************************************************************/
/* PUBLIC FUNCTIONS                                                     */
/************************************************************************/

/**
 * Initializes the credential structure
 * \param cred credential structure
 */
void _lcmapsd_init_cred(cred_t *cred)	{
    cred->proxyfile=NULL;
    cred->DN=NULL;
    cred->FQAN=NULL;
    cred->nfqan=0;
    cred->sgids=NULL;
    cred->nsgid=0;
}

/**
 * Initializes the credential structure
 * \param cred credential structure
 */
void _lcmapsd_free_cred(cred_t *cred)	{
    int i;
    free(cred->proxyfile);	    cred->proxyfile=NULL;
    free(cred->DN);		    cred->DN=NULL;
    for (i=0; i<cred->nfqan; i++)   {
	free(cred->FQAN[i]);	    cred->FQAN[i]=NULL;
    }
    cred->nfqan=0;
    free(cred->sgids);		    cred->sgids=NULL;
}

/**
 * Changes ownership of proxyfile to target uid and gid
 * \param cred credential structure
 * \err errno in case of error
 * \return LCMAPSD_SUCCESS on success or LCMAPSD_CHOWN_ERR on error
 */
lcmapsd_err_t _lcmapsd_chown(cred_t *cred, int *err)	{
    /* chown file */
    if (chown(cred->proxyfile, cred->uid, cred->gid)!=0)	{
	*err=errno;
	return LCMAPSD_CHOWN_ERR;
    }

    /* All done */
    return LCMAPSD_SUCCESS;
}

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
lcmapsd_err_t _lcmapsd_rename(cred_t *cred, const char *fmt, int *err) {
    char *newfile=NULL,*buffer=NULL;
    int len,fd;
    struct stat buf;

    /* Check we need to do something */
    if (cred->proxyfile==NULL || fmt==NULL)
	return LCMAPSD_NO_ACTION;
    
    /* Open old file */
    if ((fd=open(cred->proxyfile,O_RDONLY))==-1 ||
	fstat(fd,&buf)==-1)    {
	*err=errno;
	return LCMAPSD_RENAME_ERR;
    }
    /* Reserve mem */
    if ((buffer=malloc(buf.st_size))==NULL) {
	*err=errno;
        return LCMAPSD_OUT_OF_MEM;
    }
    /* Read old file */
    if (read(fd,buffer,buf.st_size)!=buf.st_size || close(fd)==-1)  {
	*err=errno;
	free(buffer);
	return LCMAPSD_RENAME_ERR;
    }

    /* Create new file: check for %d first */
    if (strstr(fmt,"%d")!=NULL)  {
        len=snprintf(newfile,0,fmt,cred->uid);
        if ( (newfile=malloc(len+1))==NULL)  {
	    *err=errno;
            return LCMAPSD_OUT_OF_MEM;
	}
        snprintf(newfile,len+1,fmt,cred->uid);
    } else { /* No %d */
        len=strlen(fmt);
        if ( (newfile=strdup(fmt))==NULL)	{
	    *err=errno;
            return LCMAPSD_OUT_OF_MEM;
	}
    }

    /* Check for XXXXXX */
    if (strcmp(&(newfile[len-6]),"XXXXXX")==0)	{
	/* Check if the newname is of the same form as the old */
	if (strncmp(newfile,cred->proxyfile,len-6)==0)	{
	    free(newfile);
	    return LCMAPSD_NO_ACTION;
	}
	fd=mkstemp(newfile);
    } else    {
	/* Check if the newname is the same as the old */
	if (strcmp(newfile,cred->proxyfile)==0)	{
	    free(newfile);
	    return LCMAPSD_NO_ACTION;
	}
	fd=open(newfile,O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    }
    /* If successful, chown it to the original file */
    if (fd==-1 || fchown(fd,buf.st_uid,buf.st_gid)==-1)	{
	*err=errno;
	free(newfile);
	return LCMAPSD_RENAME_ERR;
    }

    /* Write buffer to file, close and unlink old file */
    if (write(fd,buffer,buf.st_size)!=buf.st_size ||
	close(fd)==-1 ||
	unlink(cred->proxyfile)==-1)	{
	*err=errno;
	return LCMAPSD_RENAME_ERR;
    }

    /* free memory and update cred->proxyfile */
    free(buffer);
    free(cred->proxyfile);
    cred->proxyfile=newfile;
    
    return LCMAPSD_SUCCESS;
}

/**
 * Calls out (via curl) to the LCMAPSd specified in opts, using the credentials
 * in cred. CURL errors may fill the errstr buffer which needs to be freed by
 * the caller. 
 * \param opts lcmapsd_opts_t containing the LCMAPSd configuration
 * \param cred contains the input (e.g. proxy) and output (uid, gid) credentials
 * \return LCMAPSD_SUCCESS or error
 */
lcmapsd_err_t _lcmapsd_curl(lcmapsd_opts_t *opts, cred_t *cred, char **errstr) {
    CURL *curl_handle=NULL;
    struct MemoryStruct chunk;
    char *extra_url=NULL,*lcmapsd_url=NULL,*name_encoded=NULL;
    int rc,len;
    long httpresp;
    char *buffer=NULL;
    
    /* Make sure errstr has well-defined value */
    *errstr=NULL;

    if (opts->url==NULL)
	return LCMAPSD_URL_UNKNOWN;

    /* init the curl session */
    if (curl_global_init(CURL_GLOBAL_ALL)!=0 ||
	(curl_handle = curl_easy_init())==NULL)
	return LCMAPSD_CURL_ERR;

    /* Initialize size of chunk */
    chunk.size=0;

    /* Reserve reading and error buffer */
    if ( (chunk.memory=(char*)malloc(1)) == NULL ||
	 (buffer=calloc(1,CURL_ERROR_SIZE))==NULL )   {
        rc=LCMAPSD_OUT_OF_MEM;
        goto _curl_cleanup;
    }

    /* Use error buffer */
    curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, buffer);

    /* In full SSL mode we specify a proxy, and no DN in URL */
    if (opts->mode == LCMAPSD_MODE_FULLSSL)	{
	extra_url=LCMAPSD_OUTPUT_FMT;

	/* cert info */
	curl_easy_setopt(curl_handle,CURLOPT_CAPATH,opts->certinfo.capath);
	curl_easy_setopt(curl_handle,CURLOPT_CAINFO,opts->certinfo.cafile);
	curl_easy_setopt(curl_handle,CURLOPT_SSLKEY,cred->proxyfile);
	curl_easy_setopt(curl_handle,CURLOPT_SSLCERT,cred->proxyfile);

	/* malloc */
	len=strlen(opts->url)+strlen(extra_url)+1;
	if ( (lcmapsd_url=(char*)malloc(len)) == NULL)  {
	    rc=LCMAPSD_OUT_OF_MEM;
	    goto _curl_cleanup;
	}

	/* Create the full url, we know it fits as we prepared the length */
	snprintf(lcmapsd_url,len,"%s%s",
		 opts->url,extra_url);
    } else  {
	extra_url=LCMAPSD_OUTPUT_FMT LCMAPSD_DN_PFX;
	/* DN ? */
	if (cred->DN==NULL) {
	    rc=LCMAPSD_MISSING_CRED;
	    goto _curl_cleanup;
	}
	/* get encoded DN */
	if  ((name_encoded=curl_easy_escape(curl_handle, cred->DN, 0))==NULL) {
	    rc=LCMAPSD_OUT_OF_MEM;
	    goto _curl_cleanup;
	}
	/* malloc */
	len=strlen(opts->url)+strlen(extra_url)+strlen(name_encoded)+1;
	if ( (lcmapsd_url=(char*)malloc(len)) == NULL)  {
	    rc=LCMAPSD_OUT_OF_MEM;
	    goto _curl_cleanup;
	}

	/* Create the full url, we know it fits as we prepared the length */
	snprintf(lcmapsd_url,len,"%s%s%s",
		 opts->url,extra_url,name_encoded);
    }

    /* Set curl options */
    curl_easy_setopt(curl_handle, CURLOPT_URL, lcmapsd_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, _curl_memwrite);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* Timeout */
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, opts->timeout);

    /* Do lookup */
    if ( curl_easy_perform(curl_handle)!=0 ||
         curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpresp)
	    != CURLE_OK )   {
	rc=LCMAPSD_CURL_ERR;
	goto _curl_cleanup;
    }

    /* Did we receive a proper answer? */
    if (httpresp==200)  {
        if (chunk.size>0 && _lcmapsd_parse_json(chunk.memory, cred) )
            rc=LCMAPSD_SUCCESS;
	else
            /* We got a 200, should have valid entry, set to try again */
            rc=LCMAPSD_PARSE_ERR;
        goto _curl_cleanup;
    }


    /* Parse the error */
    switch (httpresp) {
        case 403:
            rc=LCMAPSD_FORBIDDEN;
            goto _curl_cleanup;
        case 0:
        default:
            rc=LCMAPSD_RESPONSE_ERR;
            goto _curl_cleanup;
    }

_curl_cleanup:
    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);

    if (rc==LCMAPSD_SUCCESS)
	free(buffer);
    else
	*errstr=buffer;

    /* Cleanup memory */
    if (chunk.memory)   free(chunk.memory);
    if (name_encoded)   free(name_encoded);
    if (lcmapsd_url)    free(lcmapsd_url);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();

    return rc;
}
