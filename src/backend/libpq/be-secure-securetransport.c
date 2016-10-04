/*-------------------------------------------------------------------------
 *
 * be-secure-securetransport.c
 *	  Secure Transport support
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * TODO:
 *		- Be able to set "not applicable" on some options like compression
 *		  which isn't supported in Secure Transport (and most likely other
 *		  SSL libraries supported in the future).
 *
 * IDENTIFICATION
 *	  src/backend/libpq/be-secure-securetransport.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#include "libpq/libpq.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/latch.h"
#include "tcop/tcopprot.h"
#include "utils/memutils.h"

#undef ACL_DELETE
#undef ACL_EXECUTE

#define Size pg_Size
#define uint64 pg_uint64
#define bool pg_bool
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#undef uint64
#undef bool
#define pg_uint64 uint64
#define pg_bool bool

/*
 * Callbacks for the Core Foundation memory allocator
 */
static void *st_allocate(CFIndex size, CFOptionFlags hint, void *info);
static void *st_reallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info);
static void st_deallocate(void *ptr, void *info);
static CFIndex st_preferredSize(CFIndex size, CFOptionFlags hint, void *info);

static void SSLLoadCertificate(Port *port);
static OSStatus load_key(Port *port, char *filename, CFArrayRef key);
static OSStatus load_certificate(Port *port, char *filename, CFArrayRef certificate);
static OSStatus load_certificate_keychain(Port *port, char *cert_name, CFArrayRef certificate);
static OSStatus load_pkcs12_file(Port *port, char *p12_fname, CFArrayRef items);
static OSStatus load_pem_file(Port *port, char *pem_fname, int size, CFArrayRef items);
static char * SSLerrmessage(OSStatus status);
static OSStatus SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len);
static OSStatus SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len);
static char * SSLerrmessage(OSStatus status);

/*
 * Private API call used in the Webkit code for creating an identity from a
 * certificate with a key. While stable and used in many open source projects
 * it should be replaced with a published API call since private APIs aren't
 * subject to the same deprecation rules.
 *
 * Can be replaced with SecIdentityCreateWithCertificate() but that requires
 * the key to be loaded into a keychain object, it can't be just in memory.
 */
extern SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator,
										SecCertificateRef certificate,
										SecKeyRef privateKey);

int
be_tls_init(bool isServerStart)
{
#ifndef __darwin__
	/*
	 * Secure Transport is only available on Darwin platforms so autoconf
	 * should protect us from ever reaching here
	 */
	Assert(false);
#endif

	return 0;
}

void
be_tls_destroy(void)
{
}

/*
 *  Attempt to negotiate a secure connection
 */
int
be_tls_open_server(Port *port)
{
	OSStatus			status;
	CFAllocatorContext *ctx;
	MemoryContext		ssl_context;
	MemoryContext		old_context;

	Assert(!port->ssl);

	Assert(PostmasterContext);
	ssl_context = AllocSetContextCreate(PostmasterContext,
										"Secure Transport SSL connection",
										ALLOCSET_SMALL_SIZES);

	old_context = MemoryContextSwitchTo(ssl_context);

	ctx = palloc0(sizeof(CFAllocatorContext));

	/*
	 * Set Core Foundation Allocator callbacks for allocating and freeing
	 * memory to use the mmgr
	 */
	ctx->allocate = st_allocate;
	ctx->deallocate = st_deallocate;
	ctx->reallocate = st_reallocate;
	ctx->preferredSize = st_preferredSize;
	
	/*
	 * retain/release callbacks are to free the memory occupied by the
	 * allocator definition itself, but since we are registering it in
	 * a per-connection defined MemoryContext we can rely on the mmgr to
	 * free the memory rather than doing it manually
	 */
	ctx->retain = NULL;
	ctx->release = NULL;

	/*
	 * copyDescription is an optional callback for returning a CFString
	 * pointer describing the allocator. Implementing this doesn't buy
	 * us anything and Core Foundation will provide a boilerplate text
	 * anyways so skip.
	 */
	ctx->copyDescription = NULL;

	/*
	 * CFAllocatorCreate() require an allocator to allocate the allocator
	 * with. Using kCFAllocatorUseContext makes it use the allocation call
	 * specified in the ctx->allocate member thus avoiding a "chicken and
	 * egg" type situation. This further means we don't need to check the
	 * returnvalue as the allocator is allocated with palloc and thus wont
	 * return on failure.
	 */
	port->stpalloc = (void *) CFAllocatorCreate(kCFAllocatorUseContext, ctx);

	port->ssl = (void *) SSLCreateContext((CFAllocatorRef) port->stpalloc, kSSLServerSide, kSSLStreamType);
	if (!port->ssl)
	{
		ereport(FATAL,
				(errmsg("could not create SSL context")));
	}

	port->ssl_in_use = true;

	/*
	 * SSLSetProtocolVersionEnabled() is marked as deprecated as of 10.9
	 * but the alternative SSLSetSessionConfig() is as of 10.11 not yet
	 * documented with the kSSLSessionConfig_xxx constants belonging to
	 * the 10.12 SDK. Rely on the deprecated version for now until the
	 * dust has properly settled around this.
	 */
	SSLSetProtocolVersionEnabled((SSLContextRef) port->ssl, kTLSProtocol12, true);

	SSLLoadCertificate(port);

	status = SSLSetIOFuncs((SSLContextRef) port->ssl, SSLSocketRead, SSLSocketWrite);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not set SSL IO functions: \"%s\"",
				 SSLerrmessage(status))));
	}


	status = SSLSetConnection((SSLContextRef) port->ssl, port);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not establish SSL connection: \"%s\"",
				 SSLerrmessage(status))));
	}

	MemoryContextSwitchTo(old_context);
	return 0;
}

/*
 *	SSLLoadCertificate
 *
 * Reads and loads the server certificate indicated by the ssl_cert_file
 * GUC as well as the private key indicated by ssl_key_file. The identity
 * created from the certificate/key is added to the cert chain for the
 * connection.
 *
 * There are no recoverable error cases from loading certificate/key so
 * the function will break out with ereport() on any errors.
 */
static void
SSLLoadCertificate(Port *port)
{
	OSStatus			status;
	CFArrayRef			certificate;
	CFArrayRef			key;
	SecIdentityRef		identity;
	SecCertificateRef	cert_ref;
	SecKeyRef			key_ref;
	SecPolicyRef		policy;
	SecTrustRef			trust;
	SecTrustResultType	trust_status;
	CSSM_TP_APPLE_EVIDENCE_INFO *status_chain;
	CFArrayRef			chain;
	CFMutableArrayRef	chain_copy;
	CFAllocatorRef		stpalloc = (CFAllocatorRef) port->stpalloc;

	status = load_certificate(port, ssl_cert_file, certificate);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not load server certificate: \"%s\"",
				 SSLerrmessage(status))));
	}

	status = load_key(port, ssl_key_file, key);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not load private key: \"%s\"",
				 SSLerrmessage(status))));
	}

	cert_ref = (SecCertificateRef) CFArrayGetValueAtIndex(certificate, 0);
	key_ref = (SecKeyRef) CFArrayGetValueAtIndex(key, 0);
	policy = SecPolicyCreateSSL(true, NULL);
	identity = SecIdentityCreate(stpalloc, cert_ref, key_ref);

	status = SecTrustCreateWithCertificates(certificate, policy, &trust);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not create trust for connection: \"%s\"",
				 SSLerrmessage(status))));
	}

	/*
	 * SecTrustEvaluate searches the user keychain for intermediate
	 * certificates, in order to use the ssl_ca_file provided we must
	 * add it to the chain before evaluating.
	 */
	if (ssl_ca_file[0])
	{
		/* TODO: read + load + add to chain */
	}

	status = SecTrustEvaluate(trust, &trust_status);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not verify certificate chain: \"%s\"",
				 SSLerrmessage(status))));
	}

	switch (trust_status)
	{
		/*
		 * Although strangely named, unspecified is the "everything worked"
		 * returnvalue where the certificate was trusted. proceed means that
		 * the user has explicitly trusted a certificate in the chain by
		 * clicking Ok in the keychain.
		 */
		case (kSecTrustResultProceed):
		case (kSecTrustResultUnspecified):
			break;

		/*
		 * recoverableTrustFailure means that the chain shouldn't be trusted
		 * as-is due to potentially fixable reasons, such an expired cert in
		 * the chain. Include an errhint to highlight.
		 */
		case (kSecTrustResultRecoverableTrustFailure):
			ereport(FATAL,
					(errmsg("could not verify certificate chain"),
					 errhint("has the root certificate expired?")));
			break;

		/*
		 * Treat all unrecoverable errors in the same manner by erroring
		 * out. The potential errors are kSecTrustResultFatalTrustFailure,
		 * kSecTrustResultDeny and kSecTrustResultOtherError.
		 */
		default:
			ereport(FATAL,
					(errmsg("could not verify certificate chain")));
			break;
	}

	status = SecTrustGetResult(trust, &trust_status, &chain, &status_chain);

	chain_copy = CFArrayCreateMutable(stpalloc, CFArrayGetCount(chain), &kCFTypeArrayCallBacks);
	
	CFArrayAppendValue(chain_copy, identity);
	if (CFArrayGetCount(chain) > 1)
		CFArrayAppendArray(chain_copy, chain, CFRangeMake(1, CFArrayGetCount(chain) - 1));

	CFRelease(chain);

	status = SSLSetCertificate((SSLContextRef) port->ssl, chain_copy);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not set certificate for connection: \"%s\"",
				 SSLerrmessage(status))));
	}
}

/*
 *	Close SSL connection.
 */
void
be_tls_close(Port *port)
{
	OSStatus ssl_status;

	if (port->ssl)
	{
		ssl_status = SSLClose((SSLContextRef) port->ssl);
		if (ssl_status != noErr)
			ereport(COMMERROR,
					(errcode(ERRCODE_PROTOCOL_VIOLATION),
					 errmsg("error in closing SSL connection: %s",
					 		SSLerrmessage(ssl_status))));

		CFRelease((SSLContextRef) port->ssl);
		port->ssl = NULL;
		port->ssl_in_use = false;
	}
}

/*
 * be_tls_get_version
 *		Retrieve the protocol version of the current connection
 */
void
be_tls_get_version(Port *port, char *ptr, size_t len)
{
	OSStatus status;
	SSLProtocol protocol;

	if (ptr == NULL || len == 0)
		return;

	if (!port->ssl)
		return;

	ptr[0] = '\0';

	status = SSLGetNegotiatedProtocolVersion((SSLContextRef) port->ssl, &protocol);
	if (status != noErr)
	{
		switch (protocol)
		{
			case kTLSProtocol11:
				strlcpy(ptr, "TLSv1.1", len);
				break;
			case kTLSProtocol12:
				strlcpy(ptr, "TLSv1.2", len);
				break;
			default:
				break;
		}
	}
}

/*
 *	Read data from a secure connection.
 */
ssize_t
be_tls_read(Port *port, void *ptr, size_t len, int *waitfor)
{
	size_t n = 0;
	OSStatus read_status;

	errno = 0;

	read_status = SSLRead((SSLContextRef) port->ssl, ptr, len, &n);
	if (read_status != noErr)
	{
		switch (read_status)
		{
			/* Function is blocked, waiting for I/O */
			case errSSLWouldBlock:
				*waitfor = WL_SOCKET_READABLE;
				errno = EWOULDBLOCK;
				if (n)
					return n;
				return -1;
				break;

			/*
			 * If the connection was closed for an unforeseen reason, return
			 * error and set errno such that the caller can raise the
			 * appropriate ereport()
			 */
			case errSSLClosedNoNotify:
			case errSSLClosedAbort:
			case errSSLClosedGraceful:
				n = -1;
				errno = ECONNRESET;
				break;

			default:
				n = -1;
				ereport(COMMERROR,
						(errcode(ERRCODE_PROTOCOL_VIOLATION),
						 errmsg("SSL error: %s",
						 		SSLerrmessage(read_status))));
				break;
		}
	}
	
	return n;
}

/*
 *	Write data to a secure connection.
 */
ssize_t
be_tls_write(Port *port, void *ptr, size_t len, int *waitfor)
{
	size_t n = 0;
	OSStatus write_status;

	errno = 0;

	write_status = SSLWrite((SSLContextRef) port->ssl, ptr, len, &n);

	/*
	 * If we recieve errSSLWouldBlock the returned n denotes the number of
	 * bytes written to the SSL context buffer and not the underlying socket.
	 * We thus need to keep initiating blank writes until we get noErr, only
	 * then do we know the data was transmitted.
	 */
	if (write_status == errSSLWouldBlock)
	{
		size_t retry_n = 0;
		while (write_status == errSSLWouldBlock)
		{
			write_status = SSLWrite((SSLContextRef) port->ssl, NULL, 0UL, &retry_n);
			/* Pause to avoid essentially spinlocking? */
		}
	}

	if (write_status != noErr)
	{
		ereport(COMMERROR,
				(errcode(ERRCODE_PROTOCOL_VIOLATION),
				 errmsg("SSL error: %s",
				 		SSLerrmessage(write_status))));
	}

	return n;
}

int be_tls_get_cipher_bits(Port *port) { return 0; }
void be_tls_get_cipher(Port *port, char *ptr, size_t len) { }
void be_tls_get_peerdn_name(Port *port, char *ptr, size_t len) { }

/*
 * be_tls_get_compression
 *		Retrieve and return whether compression is used for the
 *		current connection.
 *
 * Since Secure Transport doesn't support compression at all, always return
 * false here. Ideally we should be able to tell the caller that the option
 * isn't applicable rather than return false, but the current SSL support
 * doesn't allow for that.
 */
bool
be_tls_get_compression(Port *port)
{
	return false;
}

/* ------------------------------------------------------------ */
/*			Internal functions - Certificate Management			*/
/* ------------------------------------------------------------ */

static OSStatus
load_key(Port *port, char *filename, CFArrayRef key)
{
	OSStatus	status;
	struct stat	stat_buf;

	if (stat(filename, &stat_buf) != 0 && errno == ENOENT)
	{
		Assert(false);
		/* Load private key from keychain */
	}
	else
	{
		/*
		 * Refuse to load files owned by users other than us or root.
		 */
		if (stat_buf.st_uid != geteuid() && stat_buf.st_uid != 0)
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("private key file \"%s\" must be owned by the database user or root",
							filename)));

		/*
		 * Require no public access to key file. If the file is owned by us,
		 * require mode 0600 or less. If owned by root, require 0640 or less
		 * to allow read access through our gid, or a supplementary gid that
		 * allows to read system-wide certificates.
		 */
		if ((stat_buf.st_uid == geteuid() && stat_buf.st_mode & (S_IRWXG | S_IRWXO)) ||
			(stat_buf.st_uid == 0 && stat_buf.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)))
			ereport(FATAL,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
				  	 errmsg("private key file \"%s\" has group or world access",
							ssl_key_file),
					 errdetail("File must have permissions u=rw (0600) or less "
					 		   "if owned by the database user, or permissions "
							   "u=rw,g=r (0640) or less if owned by root.")));

		/*
		 * The key file is deemed to have the correct permissions to be
		 * trusted, let's read it.
		 */
		if (strstr(filename, ".p12") != NULL)
			status = load_pkcs12_file(port, filename, key);
		else
			status = load_pem_file(port, ssl_cert_file, stat_buf.st_size, key);
	}

	return status;
}

/*
 *	load_certificate
 *
 * Extracts a certificate from either a file on the filesystem or the
 * keychain. The certificate is returned in the "certificate" ArrayRef.
 */
static OSStatus
load_certificate(Port *port, char *filename, CFArrayRef certificate)
{
	OSStatus	status;
	struct stat	stat_buf;

	/*
	 * If the configured ssl_cert_file filename is set to a non-existing
	 * filename, assume it's a Keychain reference and attempt to load a
	 * certificate from the Keychain instead. For macOS it would make sense
	 * to reverse this logic as Keychain is the certificate store, but this
	 * implementation is intended as a drop-in replacement for the current
	 * OpenSSL based implementation so let's keep it file-first.
	 */
	if (stat(ssl_cert_file, &stat_buf) != 0 && errno == ENOENT)
	{
		status = load_certificate_keychain(port, ssl_cert_file, certificate);
	}
	else if (S_ISREG(stat_buf.st_mode))
	{
		/*
		 * If the file extension is .p12 then assume it's a PKCS12 file,
		 * else try to load as PEM file.
		 */
		if (strstr(filename, ".p12") != NULL)
			status = load_pkcs12_file(port, filename, certificate);
		else
			status = load_pem_file(port, ssl_cert_file, stat_buf.st_size, certificate);
	}
	else
	{
		ereport(FATAL,
				(errcode_for_file_access(),
				 errmsg("could not load server certificate file \"%s\": %m",
				 ssl_cert_file)));
	}

	return status;
}

static OSStatus
load_certificate_keychain(Port *port, char *cert_name, CFArrayRef certificate)
{
	/* TODO: use SecItemCopyMatching */ 
	return errSSLInternal;
}

/*
 *	load_pkcs12_file
 *
 * Read and return the items from a PKCS12 file on the local filesystem. This
 * currently doesn't handle passphrase protected files which is a TODO.
 */
static OSStatus
load_pkcs12_file(Port *port, char *p12_fname, CFArrayRef items)
{
	OSStatus		status;
	CFURLRef		p12_ref;
	CFDataRef		buf;
	CFAllocatorRef	stpalloc = (CFAllocatorRef) port->stpalloc;

	const void	   *keys[] = {};
	const void	   *vals[] = {};

	CFDictionaryRef opt = CFDictionaryCreate(NULL, keys, vals, 0, NULL, NULL);

	p12_ref = CFURLCreateFromFileSystemRepresentation(stpalloc,
					(UInt8 *) p12_fname, strlen(p12_fname), false);

	if (CFURLCreateDataAndPropertiesFromResource(stpalloc, p12_ref, &buf, NULL, NULL, &status))
	{
		status = SecPKCS12Import(buf, opt, &items);
		CFRelease(buf);
	}

	CFRelease(opt);
	CFRelease(p12_ref);

	return status;
}

static OSStatus
load_pem_file(Port *port, char *pem_fname, int size, CFArrayRef items)
{
	OSStatus							status;
	File								cert_fd;
	UInt8							   *cert_buf;
	int									ret;
	CFDataRef							data_ref;
	SecItemImportExportKeyParameters	params;
	CFStringRef							cert_path;
	SecExternalFormat					format;
	CFAllocatorRef						stpalloc = (CFAllocatorRef) port->stpalloc;
	SecExternalItemType					item_type;

	cert_buf = palloc(size);

	cert_fd = PathNameOpenFile(pem_fname, O_RDONLY, 0600);
	if (cert_fd < 0)
		ereport(FATAL,
				(errcode_for_file_access(),
				 errmsg("could not load server certificate file \"%s\": %m",
				 pem_fname)));

	ret = FileRead(cert_fd, (char *) cert_buf, size);

	/*
	 * TODO: Handle reading the certificate in chunks
	 */
	if (ret != size)
	{
		FileClose(cert_fd);
		return errSecInternalError;
	}

	FileClose(cert_fd);

	data_ref = CFDataCreate(stpalloc, cert_buf, size);

	memset(&params, 0, sizeof(SecItemImportExportKeyParameters));
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	/* Set OS default access control on the imported key */
	params.flags = kSecKeyNoAccessControl;

	/*
	 * SecItemImport takes two optional hints for interpreting the type of
	 * certificate loaded. format holds a constant identifying the format
	 * or NULL if unknown, the format variable will contain the format which
	 * SecItemImport decided to imoprt the certificate as regardless of
	 * initial value. cert_path either contains the full filename from which
	 * the certificate data was read or the file extension.
	 */
	format = kSecFormatPEMSequence;
	cert_path = CFStringCreateWithCString(stpalloc, pem_fname,
										  kCFStringEncodingUTF8);

	item_type = kSecItemTypeCertificate;

	/*
	 * We are currently not importing the certificate into a keychain but
	 * a future TODO is to create a transient keychain which exists for
	 * the duration of the server process for holding the certificates.
	 */
	status = SecItemImport(data_ref, cert_path, &format, &item_type,
						   0 /* flags */, &params, NULL /* keychain */,
						   &items);

	CFRelease(cert_path);
	CFRelease(data_ref);

	return status;
}

/* ------------------------------------------------------------ */
/*				Internal functions - Translation				*/
/* ------------------------------------------------------------ */

/*
 * SSLerrmessage
 *		Create and return a human readable error message given
 *		the specified status code
 *
 * While only interesting to use for error cases, the function will return a
 * translation for non-error statuses as well like noErr and errSecSuccess.
 */
static char *
SSLerrmessage(OSStatus status)
{
	CFStringRef		err_msg;
	char		   *err_buf;

	err_msg = SecCopyErrorMessageString(status, NULL);

	if (err_msg)
	{
		err_buf = pstrdup(CFStringGetCStringPtr(err_msg, kCFStringEncodingUTF8));
		CFRelease(err_msg);
	}
	else
		err_buf = pstrdup(_("unknown SSL error"));
	
	return err_buf;
}

/* ------------------------------------------------------------ */
/*				Internal functions - Socket IO					*/
/* ------------------------------------------------------------ */

/*
 *	SSLSocketRead
 *
 * Callback for reading data from the connection. When entering the function,
 * len is set to the number of bytes requested. Upon leaving, len should be
 * overwritten with the actual number of bytes read.
 */
static OSStatus
SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len)
{
	OSStatus	status;
	int			res;

	res = secure_raw_read((Port *) conn, data, *len);

	if (res < 0)
	{
		/*
		 * TODO: Figure out if there is a case where it's reasonable to
		 * return errSSLClosedGraceful
		 */
		switch (errno)
		{
#ifdef EAGAIN
			case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
			case EWOULDBLOCK:
#endif
			case EINTR:
				status = errSSLWouldBlock;
				break;

			default:
				status = errSSLClosedAbort;
				break;
		}

		*len = 0;
	}
	else
	{
		status = noErr;
		*len = res;
	}

	return status;
}


static OSStatus
SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len)
{
	OSStatus	status;
	int			res;

	res = secure_raw_write((Port *) conn, data, *len);

	if (res < 0)
	{
		switch (errno)
		{
#ifdef EAGAIN
			case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
			case EWOULDBLOCK:
#endif
			case EINTR:
				status = errSSLWouldBlock;
				break;
			
			default:
				status = errSSLClosedAbort;
				break;
		}

		*len = res;
	}
	else
	{
		status = noErr;
		*len = res;
	}

	return status;
}

/* ------------------------------------------------------------ */
/*			Internal functions - Memory Allocation				*/
/* ------------------------------------------------------------ */

/*
 * Core Foundation memory allocator callbacks. Memory allocations inside the
 * Secure Transport framework can either be backed by the default allocator
 * in core foundation, or via a custom allocator defined via a CFAllocatorRef.
 * To keep the memory under our mmgr control, set up callbacks to their mmgr
 * counterparts.
 *
 * The 'CFOptionFlags hint' parameter is intentionally not considered per the
 * API documentation.
 */

static void *
st_allocate(CFIndex size, CFOptionFlags hint, void *info)
{
	/*
	 * While palloc(0) is a legitimate operation, a zero allocation is per
	 * the Core Foundation allocator documentation not legal and any such
	 * request is required to return NULL.
	 */
	if (size <= 0)
		return NULL;
	
	return palloc(size);
}

static void *
st_reallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info)
{
	/*
	 * While repalloc with a NULL pointer is forbidden, a core foundation
	 * allocator allows it so we must implement its expected API. On zero
	 * size NULL is expected and for non-zero the ptr should be allocated
	 * as if the user called the allocate callback.
	 */
	if (ptr == NULL)
	{
		if (newsize <= 0)
			return NULL;
	
		return st_allocate(newsize, hint, info);
	}

	/*
	 * If the pointer is non-NULL but the size is zero, the expectation
	 * is to deallocate (free) the allocation rather than reallocate down
	 * to zero for later reallocations to a greater size.
	 */
	if (newsize == 0)
	{
		st_deallocate(ptr, info);
		return NULL;
	}

	return repalloc(ptr, newsize);
}

static void
st_deallocate(void *ptr, void *info)
{
	if (ptr == NULL)
		return;

	pfree(ptr);
}

static CFIndex
st_preferredSize(CFIndex size, CFOptionFlags hint, void *info)
{
	/* TODO: Return something sensible */
	return size;
}
