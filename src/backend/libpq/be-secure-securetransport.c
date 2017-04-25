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
 *		- Support memory allocation in Secure Transport via a custom CF
 *		  allocator which is backed by a MemoryContext.
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

#include "common/base64.h"
#include "libpq/libpq.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/latch.h"
#include "tcop/tcopprot.h"
#include "utils/backend_random.h"
#include "utils/memutils.h"

#undef ACL_DELETE
#undef ACL_EXECUTE

#define Size pg_Size
#define uint64 pg_uint64
#define bool pg_bool
#include <Security/cssmerr.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#undef uint64
#undef bool
#define pg_uint64 uint64
#define pg_bool bool

/* ------------------------------------------------------------ */
/*				Struct definitions and Static variables			*/
/* ------------------------------------------------------------ */

/*
 * SSL Context variables. Secure Transport doesn't have a corresponding context
 * to the OpenSSL SSL_CTX (Keychains are not analogous as they are mere file-
 * based containers for secrets, not runtime context stores). Create our own
 * SSL context store instead.
 */
typedef struct SSL_Context
{
	/* Certificates */
	CFArrayRef			root_certificates;
	CFArrayRef			certificates;
	CFArrayRef			keys;
	CFArrayRef			crl;

	CFMutableArrayRef	chain;
} SSL_Context;

static SSL_Context *ssl_context;

/*
 * For Secure Transport API functions we rely on SecCopyErrorMessageString()
 * which will pull a human readable error message for the individual error
 * statuses. For our static functions, we mimic the behaviour by passing
 * errSecInternalError and setting the error message in internal_err.
 */
#define ERR_MSG_LEN 128
static char internal_err[ERR_MSG_LEN];


/* ------------------------------------------------------------ */
/*							Prototypes							*/
/* ------------------------------------------------------------ */

extern SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);
 
static OSStatus SSLLoadCertificate(SSL_Context **context, bool isServerStart);
static void SSL_context_free(SSL_Context *c);
static OSStatus load_certificate(char *name, CFArrayRef *cert_array);
static OSStatus load_key(char *name, CFArrayRef *out);

static char * SSLerrmessage(OSStatus status);
static OSStatus SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len);
static OSStatus SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len);
static char * SSLerrmessage(OSStatus status);
static const char * SSLciphername(SSLCipherSuite cipher);

static UInt8 *pem_to_der(const char *in, int *offset);

/* ------------------------------------------------------------ */
/*					Hardcoded DH parameters						*/
/* ------------------------------------------------------------ */

/*
 * Secure Transport doesn't support setting different keysizes for DH like
 * the OpenSSL callback, instead a single keysize is set and there doesn't
 * seem to be any negotiation from that?
 */
static const uint8_t file_dh2048[] =
	"\x30\x82\x01\x08\x02\x82\x01\x01\x00\xa3\x09\x9b\x20\x73\xdd\x59"
	"\x1b\x91\x05\x5b\x6c\x5f\xe7\xd7\xea\xaa\x01\x73\xe3\xf5\x89\xbe"
	"\xc7\xb5\x38\x12\xf5\x28\x40\x03\x32\x89\x48\x39\x77\xb7\xa3\xa0"
	"\x83\x5f\xff\xbe\x03\xe2\xa5\xf6\x64\xb7\xba\xbd\xb7\xeb\x57\x42"
	"\xe3\x16\x12\xc3\x9d\xba\x06\xf0\xbb\xab\x13\x98\x0a\xcc\x6c\x63"
	"\xb9\xca\xb0\x39\x86\x9e\xb7\xa0\x23\x96\xd5\xce\x24\x44\x2a\x05"
	"\x1c\xe5\x69\x5d\xd1\x83\x8c\xc1\x92\xb1\xd6\x18\xe5\x4e\xc8\xeb"
	"\x21\xe8\x16\x87\x69\x4f\x86\x95\x25\x10\xdb\x1e\x49\x1c\x80\x3e"
	"\x9a\x3d\x43\x66\xf7\x45\x0d\x37\x61\x37\xad\xce\x31\xec\x3b\xbd"
	"\x55\x08\xe9\xb2\x97\xf0\xfc\x59\x8e\xd3\x73\xe2\x4a\x9b\x58\xbb"
	"\x0a\x34\xb7\xea\x42\x94\xf9\xf5\xba\xf2\x06\xd9\xe6\xf1\xa7\x4a"
	"\x6f\xd4\x72\x1f\x8d\x20\x63\x85\x29\xe5\x90\x59\xc0\x36\x3e\x16"
	"\x5c\xa4\x46\xac\x44\x8c\x89\x00\x5d\xa2\xe9\x5b\xf0\xe4\x8c\xea"
	"\xa6\x37\xac\xf8\x2a\x33\xbb\x39\xc6\xdf\x14\x96\x64\x13\x9e\x99"
	"\xd8\xdd\x94\x61\xfe\xa1\x87\x48\xb6\x65\x69\xc7\xe7\x49\x53\xcf"
	"\xa8\xa1\xc0\x9d\xf6\x7c\x29\xfc\xb2\x74\xb1\x2d\xe5\x0c\xd0\x32"
	"\xc4\x35\x85\x82\x30\x07\x60\x01\x93\x02\x01\x02";


/* ------------------------------------------------------------ */
/*							Backend API							*/
/* ------------------------------------------------------------ */

/*
 * be_tls_init
 *		Initialize the SSL context
 *
 * This function is responsible for initializing the SSL context by reading the
 * the CA, server certificate+key and CRL.
 */
int
be_tls_init(bool isServerStart)
{
	OSStatus			status;
	SSL_Context		   *context;
	SecIdentityRef		identity;

	memset(internal_err, '\0', sizeof(internal_err));

#ifndef __darwin__
	/*
	 * Secure Transport is only available on Darwin platforms so autoconf
	 * should protect us from ever reaching here
	 */
	Assert(false);
#endif

	context = palloc(sizeof(SSL_Context));

	status = SSLLoadCertificate(&context, isServerStart);
	if (status != noErr)
		goto error;

return 0;
	/*
	 * We now have a certificate and either a private key, or a search path
	 * which should contain it.
	 */
	identity = SecIdentityCreate(NULL, (SecCertificateRef) CFArrayGetValueAtIndex(context->certificates, 0),
								 (SecKeyRef) CFArrayGetValueAtIndex(context->keys, 0));
	if (identity == NULL)
	{
		ereport(isServerStart ? FATAL : LOG,
				(errmsg("could not create identity: \"%s\"",
				 SSLerrmessage(status))));
	}
	CFRetain(identity);

	context->chain = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	/*
	 * SSLSetCertificates set the certificate(s) to use for the connection.
	 * The first element in the passed array is required to be the identity
	 * with elements 1..n being certificates.
	 */
	CFArrayInsertValueAtIndex(context->chain, 0, identity);

	CFArrayAppendArray(context->chain, context->certificates,
					   CFRangeMake(0, CFArrayGetCount(context->certificates)));

	/*
	 * Load the Certificate Authority if configured
	 */
	if (ssl_ca_file[0])
	{
		status = load_certificate(ssl_ca_file, &context->root_certificates);
		if (status != noErr)
		{
			ereport(isServerStart ? FATAL : LOG,
					(errmsg("could not load root certificate (%d): \"%s\"",
					 status, SSLerrmessage(status))));
			goto error;
		}
		
		CFArrayAppendArray(context->chain, context->root_certificates,
						   CFRangeMake(0, CFArrayGetCount(context->root_certificates)));
	}

	/*
	 * Load the Certificate Revocation List in case configured.
	 */
	if (ssl_crl_file[0])
	{
		ereport(isServerStart ? FATAL : LOG,
				(errmsg("CRL files not supported yet")));
		goto error;
	}

	/*
	 * Set flag to remember whether Certificate Authority has been loaded
	 */
	if (ssl_ca_file[0])
		ssl_loaded_verify_locations = true;
	else
		ssl_loaded_verify_locations = false;

	if (ssl_context)
		SSL_context_free(ssl_context);
	ssl_context = context;

	return 0;

error:

	SSL_context_free(context);
	return -1;
}

static void
SSL_context_free(SSL_Context *c)
{
	/* XXX: implement me */
}

/*
 * be_tls_destroy
 *		Tear down global Secure Transport structures and return resources.
 */
void
be_tls_destroy(void)
{
	if (!ssl_context)
		return;

	SSL_context_free(ssl_context);
	ssl_loaded_verify_locations = false;
}

/*
 * bt_tls_open_server
 *		Attempt to negotiate a secure connection
 */
int
be_tls_open_server(Port *port)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecTrustResultType	trust_eval = 0;

	Assert(!port->ssl);

	port->ssl = (void *) SSLCreateContext(NULL, kSSLServerSide, kSSLStreamType);
	if (!port->ssl)
		ereport(FATAL,
				(errmsg("could not create SSL context")));

	port->ssl_in_use = true;
	port->ssl_buffered = 0;

	/* XXX: correct? */
	if (ssl_loaded_verify_locations)
		SSLSetClientSideAuthenticate((SSLContextRef) port->ssl, kAlwaysAuthenticate);

	/*
	 * TODO: This loads a pregenerated DH parameter, code for loading the
	 * dh files needs to be added.
	 */
	SSLSetDiffieHellmanParams((SSLContextRef) port->ssl, file_dh2048, sizeof(file_dh2048));

	/*
	 * SSLSetProtocolVersionEnabled() is marked as deprecated as of 10.9
	 * but the alternative SSLSetSessionConfig() is as of 10.11 not yet
	 * documented with the kSSLSessionConfig_xxx constants belonging to
	 * the 10.12 SDK. Rely on the deprecated version for now until the
	 * dust has properly settled around this.
	 */
	SSLSetProtocolVersionEnabled((SSLContextRef) port->ssl, kTLSProtocol12, true);

	status = SSLSetCertificate((SSLContextRef) port->ssl, (CFArrayRef) ssl_context->chain);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not set certificate for connection: \"%s\"",
				 SSLerrmessage(status))));
	}

	status = SSLSetIOFuncs((SSLContextRef) port->ssl, SSLSocketRead, SSLSocketWrite);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not set SSL IO functions: \"%s\"",
				 SSLerrmessage(status))));
	}

	status = SSLSetSessionOption((SSLContextRef) port->ssl, kSSLSessionOptionBreakOnClientAuth, true);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not set SSL certificate validation: \"%s\"",
				 SSLerrmessage(status))));
	}

	status = SSLSetConnection((SSLContextRef) port->ssl, port);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not establish SSL connection: \"%s\"",
				 SSLerrmessage(status))));
	}

	/*
	 * Perform handshake
	 */
	for (;;)
	{
		status = SSLHandshake((SSLContextRef) port->ssl);
		if (status == noErr)
			break;

		if (status == errSSLWouldBlock || status == -1)
			continue;

		if (status == errSSLClosedAbort || status == errSSLClosedGraceful)
			return -1;

		ereport(LOG, (errmsg("XXX: handshake status: %d", status)));

		if (status == errSSLPeerAuthCompleted)
		{
			ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted logic")));
			status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
			if (status != noErr || trust == NULL)
			{
			ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 1")));
				ereport(WARNING,
					(errmsg("SSLCopyPeerTrust returned: \"%s\"",
					 SSLerrmessage(status))));
				return -1;
			}

			if (ssl_loaded_verify_locations)
			{
				ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 2")));
				status = SecTrustSetAnchorCertificates(trust, ssl_context->root_certificates);
				if (status != noErr)
				{
					ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 3")));
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificates returned: \"%s\"",
						 SSLerrmessage(status))));
					return -1;
				}

				status = SecTrustSetAnchorCertificatesOnly(trust, false);
				if (status != noErr)
				{
					ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 4")));
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificatesOnly returned: \"%s\"",
						 SSLerrmessage(status))));
					return -1;
				}
			}

			status = SecTrustEvaluate(trust, &trust_eval);
			if (status != noErr)
			{
				ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 5")));
				ereport(WARNING,
					(errmsg("SecTrustEvaluate failed, returned: \"%s\"",
					 SSLerrmessage(status))));
				return -1;
			}

			switch (trust_eval)
			{
				/*
				 * If 'Unspecified' then an anchor certificate was reached without
				 * encountering any explicit user trust. If 'Proceed' then the user
				 * has chosen to explicitly trust a certificate in the chain by
				 * clicking "Trust" in the Keychain app.
				 */
				case kSecTrustResultUnspecified:
				case kSecTrustResultProceed:
					port->peer_cert_valid = true;
					break;

				/*
				 * 'Confirm' indicates that an interactive confirmation from the
				 * user is requested. This result code was deprecated in 10.9
				 * however so treat it as a Deny to avoid having to invoke UI
				 * elements from the Keychain.
				 */
				case kSecTrustResultConfirm:
				/*
				 * 'RecoverableTrustFailure' indicates that the certificate was
				 * rejected but might be trusted with minor changes to the eval
				 * context (ignoring expired certificate etc). TODO: Opening up to
				 * changing the eval context here seems dangerous but we can do
				 * better logging of the error by invoking SecTrustGetTrustResult()
				 * to get info on exactly what failed; call and extract relevant
				 * information to the logstring.
				 */
				case kSecTrustResultRecoverableTrustFailure:
					/* XXX TODO */
					port->peer_cert_valid = true;
					break;
				/*
				 * Treat all other cases as rejection without further questioning.
				 */
				default:
					port->peer_cert_valid = false;
					break;
			}

			if (port->peer_cert_valid)
			{
				ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 6")));
				SecCertificateRef usercert = SecTrustGetCertificateAtIndex(trust, 0L);

				CFStringRef usercert_cn;
				SecCertificateCopyCommonName(usercert, &usercert_cn);
				port->peer_cn = pstrdup(CFStringGetCStringPtr(usercert_cn, kCFStringEncodingUTF8));

				CFRelease(usercert_cn);
			}
		}
	}

	if (status != noErr)
	{
		ereport(LOG, (errmsg("XXX: in errSSLPeerAuthCompleted 7")));
		return -1;
	}

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
static OSStatus
SSLLoadCertificate(SSL_Context **context, bool isServerStart)
{
	OSStatus			status;
	SSL_Context		   *c = *context;

	/*
	 * An identity in Secure Transport is a container consisting of a private
	 * key, a public key and a certificate. The preferred way to transport an
	 * identity in macOS is to either use a PKCS12 file or a Keychain. Since
	 * we want to maintain drop-in replacement compatability with the OpenSSL
	 * implementation we however need to support reading the certificate and
	 * key files separately and creating the identity from that. A future TODO
	 * is to support reading PKCS12 files directly.
	 */
	status = load_certificate(ssl_cert_file, &c->certificates);
	if (status != noErr)
	{
		if (status == errSecDuplicateItem)
			ereport(WARNING, (errmsg("certificate and CA share name")));
		else
		{
			ereport(isServerStart ? FATAL : LOG,
					(errmsg("certificate load failed: \"%s\"", SSLerrmessage(status))));
			return status;
		}
	}

	if (CFArrayGetCount(c->certificates) == 0)
	{
		ereport(isServerStart ? FATAL : LOG,
				(errmsg("certificate failed to load")));
		return errSecInternalError;
	}

	status = load_key(ssl_key_file, &c->keys);
	if (status != noErr)
	{
		ereport(isServerStart ? FATAL : LOG,
				(errmsg("key load failed: \"%s\"", SSLerrmessage(status))));
		return status;
	}

	return noErr;
}

/*
 *
 * TODO: figure out better returncodes
 */
static OSStatus
load_key(char *name, CFArrayRef *out)
{
	OSStatus			status;
	struct stat			stat_buf;
	int					ret;
	UInt8			   *buf;
	FILE			   *fd;
	CFDataRef			data;
	SecExternalFormat	format;
	SecExternalItemType	type;
	CFStringRef			path;

	ret = stat(name, &stat_buf);
	if (ret != 0)
	{
		/*
		 * The key name is referencing a non-existing file, which we assume to
		 * mean that it's referencing a Keychain label. We could search the
		 * user default Keychain here to verify but since identity creation
		 * will do just that anyways we might as well defer the key search to
		 * that stage. Return to go ahead with identity creation.
		 */
		if (errno == ENOENT)
			return errSecSuccess;

		strlcpy(internal_err, _("unable to stat key file"), sizeof(internal_err));
		return errSecInternalError;
	}

	if (!S_ISREG(stat_buf.st_mode))
	{
		strlcpy(internal_err, _("key file is not a regular file"), sizeof(internal_err));
		return errSecInternalError;
	}

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
						name),
				 errdetail("File must have permissions u=rw (0600) or less "
						   "if owned by the database user, or permissions "
						   "u=rw,g=r (0640) or less if owned by root.")));

	if ((fd = fopen(name, "r")) < 0)
		return errSecInternalError;

	buf = palloc(stat_buf.st_size);

	ret = fread(buf, 1, stat_buf.st_size, fd);
	fclose(fd);

	if (ret != stat_buf.st_size)
		return errSecInternalError;

	type = kSecItemTypePrivateKey;
	format = kSecFormatPEMSequence;
	path = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	data = CFDataCreate(NULL, buf, stat_buf.st_size);

	SecItemImportExportKeyParameters params;
	memset(&params, 0, sizeof(SecItemImportExportKeyParameters));
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	/* Set OS default access control on the imported key */
	params.flags = kSecKeyNoAccessControl;

	status = SecItemImport(data, path, &format, &type, 0, &params, NULL, out);

	CFRelease(path);
	CFRelease(data);

	return status;
}

/*
 *	load_certificate
 *		Extracts a certificate from either a file on the filesystem or
 *		a keychain.
 *
 * TODO: figure out better returncodes
 */
static OSStatus
load_certificate(char *name, CFArrayRef *cert_array)
{
	SecCertificateRef	certificate;
	struct stat			stat_buf;
	int					ret;
	int					offset;
	UInt8			   *buf;
	FILE			   *fd;
	CFDataRef			data;

	/*
	 * If the configured ssl_cert_file filename is set to a non-existing
	 * file, assume it's referencing a Keychain label and attempt to load
	 * the certificate from the Keychain instead. 
	 */
	ret = stat(name, &stat_buf);
	if (ret != 0 && errno == ENOENT)
	{
		/* XXX: Search for the certificate in keychains */
		return errSecInternalError;
	}
	else if (ret == 0 && S_ISREG(stat_buf.st_mode))
	{
		if ((fd = fopen(name, "r")) < 0)
			return errSecInternalError;

		buf = palloc(stat_buf.st_size);
		ret = fread(buf, 1, stat_buf.st_size, fd);
		fclose(fd);

		if (ret != stat_buf.st_size)
			return errSecInternalError;

		/*
		 * If the file extension isn't .der we assume that the loaded file is
		 * in pem format. Secure Transport require the individual certificates
		 * in the pem bundle in der format, so convert each.
		 */
		if (pg_strncasecmp(name + (strlen(name) - 4), ".der", 4) != 0)
		{
			offset = 0;
			while (offset < stat_buf.st_size)
			{
				UInt8 *der = pem_to_der((const char *) buf + offset, &offset);
				if (!der)
				{
					if (offset < (stat_buf.st_size - 1))
						return errSSLBadCert;
					break;
				}

				data = CFDataCreate(NULL, der, sizeof(der));

				CSSM_DATA d;

				d.Data = (unsigned char *) &der;
				d.Length = sizeof(der);

				OSStatus status = SecCertificateCreateFromData(&d, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &certificate);
				if (status != noErr || !certificate)
					return errSSLBadCert;

				/*
				certificate = SecCertificateCreateWithData(NULL, data);
				if (!certificate)
					return errSSLBadCert;
				*/
				*cert_array = CFArrayCreate(NULL, (const void **) &certificate, 1, &kCFTypeArrayCallBacks);
				CFRelease(data);
				CFRelease(certificate);
				pfree(der);
			}
		}
		else
		{
			/* Certificate is assumed to be in DER format */
			data = CFDataCreate(NULL, buf, stat_buf.st_size);
			certificate = SecCertificateCreateWithData(NULL, data);
			if (!certificate)
				return errSSLBadCert;
			*cert_array = CFArrayCreate(NULL, (const void **) &certificate, 1, &kCFTypeArrayCallBacks);
			CFRelease(data);
			CFRelease(certificate);
		}
	}
	else
		return errSecInternalError;

	return errSecSuccess;
}


/*
 *	Close SSL connection.
 */
void
be_tls_close(Port *port)
{
	OSStatus		ssl_status;

	if (!port->ssl)
		return;

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

	if (!(SSLContextRef) port->ssl)
	{
		ptr[0] = '\0';
		return;
	}

	status = SSLGetNegotiatedProtocolVersion((SSLContextRef) port->ssl, &protocol);
	if (status == noErr)
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
				strlcpy(ptr, "Unknown", len);
				break;
		}
	}
	else
		ptr[0] = '\0';
}

/*
 *	Read data from a secure connection.
 */
ssize_t
be_tls_read(Port *port, void *ptr, size_t len, int *waitfor)
{
	size_t			n = 0;
	ssize_t			ret;
	OSStatus		read_status;
	SSLContextRef	ssl = (SSLContextRef) port->ssl;

	errno = 0;

	if (len <= 0)
		return 0;

	read_status = SSLRead(ssl, ptr, len, &n);
	switch (read_status)
	{
		case noErr:
			ret = n;
			break;

		/* Function is blocked, waiting for I/O */
		case errSSLWouldBlock:
			if (port->ssl_buffered)
				*waitfor = WL_SOCKET_WRITEABLE;
			else
				*waitfor = WL_SOCKET_READABLE;

			errno = EWOULDBLOCK;
			if (n == 0)
				ret = -1;
			else
				ret = n;

			break;

		case errSSLClosedGraceful:
			ret = 0;
			break;

		/*
		 * If the connection was closed for an unforeseen reason, return
		 * error and set errno such that the caller can raise the
		 * appropriate ereport()
		 */
		case errSSLClosedNoNotify:
		case errSSLClosedAbort:
			ret = -1;
			errno = ECONNRESET;
			break;

		default:
			ret = -1;
			ereport(COMMERROR,
					(errcode(ERRCODE_PROTOCOL_VIOLATION),
					 errmsg("SSL error: %s",
							SSLerrmessage(read_status))));
			break;
	}

	return ret;
}

/*
 *	Write data to a secure connection.
 */
ssize_t
be_tls_write(Port *port, void *ptr, size_t len, int *waitfor)
{
	size_t		n = 0;
	OSStatus	write_status;

	errno = 0;

	if (len == 0)
		return 0;

	if (port->ssl_buffered > 0)
	{
		write_status = SSLWrite((SSLContextRef) port->ssl, NULL, 0, &n);

		if (write_status == noErr)
		{
			n = port->ssl_buffered;
			port->ssl_buffered = 0;
		}
		else if (write_status == errSSLWouldBlock || write_status == -1)
		{
			n = -1;
			errno = EINTR;
		}
		else
		{
			n = -1;
			errno = ECONNRESET;
		}
	}
	else
	{
		write_status = SSLWrite((SSLContextRef) port->ssl, ptr, len, &n);

		switch (write_status)
		{
			case noErr:
				break;

			case -1:
			case errSSLWouldBlock:
				port->ssl_buffered = len;
				n = 0;
#ifdef EAGAIN
				errno = EAGAIN;
#else
				errno = EINTR;
#endif
				break;

			/*
			 * Clean disconnections
			 */
			case errSSLClosedNoNotify:
				/* fall through */
			case errSSLClosedGraceful:
				errno = ECONNRESET;
				n = -1;
				break;

			default:
				errno = ECONNRESET;
				n = -1;
				break;
		}
	}

	return n;
}

/*
 * be_tls_get_cipher_bits
 *
 */
int
be_tls_get_cipher_bits(Port *port)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	SecKeyRef			key;
	int					keysize = 0;

	status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
	if (status == noErr)
	{
		cert = SecTrustGetCertificateAtIndex(trust, 0);
		status = SecCertificateCopyPublicKey(cert, &key);
		if (status == noErr)
			keysize = SecKeyGetBlockSize(key);
	}

	return keysize;
}

/*
 * bt_tls_get_peerdn_name
 *
 */
void
be_tls_get_peerdn_name(Port *port, char *ptr, size_t len)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	CFStringRef			dn_str;

	status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
	if (status == noErr)
	{
		/*
		 * TODO: copy the certificate parts with SecCertificateCopyValues and
		 * parse the OIDs to build up the DN
		 */
		cert = SecTrustGetCertificateAtIndex(trust, 0);
		dn_str = SecCertificateCopyLongDescription(NULL, cert, NULL);
		strlcpy(ptr, CFStringGetCStringPtr(dn_str, kCFStringEncodingASCII), len);
		CFRelease(dn_str);
	}
	else
		ptr[0] = '\0';
}

/*
 * be_tls_get_cipher
 *		Return the negotiated ciphersuite for the current connection.
 *
 * Returns NULL in case we weren't able to either get the negotiated cipher, or
 * translate it into a human readable string.
 */
void
be_tls_get_cipher(Port *port, char *ptr, size_t len)
{
	OSStatus		status;
	SSLCipherSuite	cipher;
	const char	   *cipher_name;

	ptr[0] = '\0';
	status = SSLGetNegotiatedCipher((SSLContextRef) port->ssl, &cipher);
	if (status != noErr)
		return;

	cipher_name = SSLciphername(cipher);
	if (cipher_name != NULL)
		strlcpy(ptr, SSLciphername(cipher), len);
}

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

	/*
	 * There is no translation for errSecUnknownFormat in at least 10.11 El
	 * Capitan, and possibly others, so we maintain our own
	 */
	if (status == -25257)
		return pstrdup(_("The item you are trying to import has an unknown format."));

	/*
	 * If the error is internal, and we have an error message in the internal
	 * buffer then return that error.
	 */
	if (status == errSecInternalError && internal_err[0])
	{
		err_buf = pstrdup(internal_err);
		memset(internal_err, '\0', ERR_MSG_LEN);
	}
	else
	{
		err_msg = SecCopyErrorMessageString(status, NULL);

		if (err_msg)
		{
			err_buf = pstrdup(CFStringGetCStringPtr(err_msg, kCFStringEncodingUTF8));
			CFRelease(err_msg);
		}
		else
			err_buf = pstrdup(_("unknown SSL error"));
	}

	return err_buf;
}

/*
 * SSLciphername
 *
 * Translate a SSLCipherSuite code into a string literal suitable for printing
 * in log/informational messages to the user. Since this implementation of the
 * Secure Transport lib doesn't support SSLv2/v3 these ciphernames are omitted.
 */
static const char *
SSLciphername(SSLCipherSuite cipher)
{
	switch (cipher)
	{
		case TLS_NULL_WITH_NULL_NULL:
			return "NULL_WITH_NULL_NULL";
			break;

		/* TLS addenda using AES, per RFC 3268 */
		case TLS_RSA_WITH_AES_128_CBC_SHA:
			return "RSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
			return "DH_DSS_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
			return "DH_RSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
			return "DHE_DSS_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
			return "DHE_RSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DH_anon_WITH_AES_128_CBC_SHA:
			return "DH_anon_WITH_AES_128_CBC_SHA";
			break;
		case TLS_RSA_WITH_AES_256_CBC_SHA:
			return "RSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
			return "DH_DSS_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
			return "DH_RSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
			return "DHE_DSS_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			return "DHE_RSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DH_anon_WITH_AES_256_CBC_SHA:
			return "DH_anon_WITH_AES_256_CBC_SHA";
			break;

		/* ECDSA addenda, RFC 4492 */
		case TLS_ECDH_ECDSA_WITH_NULL_SHA:
			return "ECDH_ECDSA_WITH_NULL_SHA";
			break;
		case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
			return "ECDH_ECDSA_WITH_RC4_128_SHA";
			break;
		case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
			return "ECDH_ECDSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
			return "ECDH_ECDSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
			return "ECDHE_ECDSA_WITH_NULL_SHA";
			break;
		case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
			return "ECDHE_ECDSA_WITH_RC4_128_SHA";
			break;
		case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_ECDH_RSA_WITH_NULL_SHA:
			return "ECDH_RSA_WITH_NULL_SHA";
			break;
		case TLS_ECDH_RSA_WITH_RC4_128_SHA:
			return "ECDH_RSA_WITH_RC4_128_SHA";
			break;
		case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
			return "ECDH_RSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
			return "ECDH_RSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_ECDHE_RSA_WITH_NULL_SHA:
			return "ECDHE_RSA_WITH_NULL_SHA";
			break;
		case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
			return "ECDHE_RSA_WITH_RC4_128_SHA";
			break;
		case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			return "ECDHE_RSA_WITH_AES_128_CBC_SHA";
			break;
		case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			return "ECDHE_RSA_WITH_AES_256_CBC_SHA";
			break;
		case TLS_ECDH_anon_WITH_NULL_SHA:
			return "ECDH_anon_WITH_NULL_SHA";
			break;
		case TLS_ECDH_anon_WITH_RC4_128_SHA:
			return "ECDH_anon_WITH_RC4_128_SHA";
			break;
		case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_anon_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
			return "ECDH_anon_WITH_AES_128_CBC_SHA";
			break;
		case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
			return "ECDH_anon_WITH_AES_256_CBC_SHA";
			break;

		/* Server provided RSA certificate for key exchange. */
		case TLS_RSA_WITH_NULL_MD5:
			return "RSA_WITH_NULL_MD5";
			break;
		case TLS_RSA_WITH_NULL_SHA:
			return "RSA_WITH_NULL_SHA";
			break;
		case TLS_RSA_WITH_RC4_128_MD5:
			return "RSA_WITH_RC4_128_MD5";
			break;
		case TLS_RSA_WITH_RC4_128_SHA:
			return "RSA_WITH_RC4_128_SHA";
			break;
		case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			return "RSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_RSA_WITH_NULL_SHA256:
			return "RSA_WITH_NULL_SHA256";
			break;
		case TLS_RSA_WITH_AES_128_CBC_SHA256:
			return "RSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_RSA_WITH_AES_256_CBC_SHA256:
			return "RSA_WITH_AES_256_CBC_SHA256";
			break;

		/*
		 * Server-authenticated (and optionally client-authenticated)
		 * Diffie-Hellman.
		 */
		case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
			return "DH_DSS_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
			return "DH_RSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
			return "DHE_DSS_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
			return "DHE_RSA_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			return "DH_DSS_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			return "DH_RSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			return "DHE_DSS_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			return "DHE_RSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			return "DH_DSS_WITH_AES_256_CBC_SHA256";
			break;
		case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			return "DH_RSA_WITH_AES_256_CBC_SHA256";
			break;
		case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			return "DHE_DSS_WITH_AES_256_CBC_SHA256";
			break;
		case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			return "DHE_RSA_WITH_AES_256_CBC_SHA256";
			break;

		/* Completely anonymous Diffie-Hellman */
		case TLS_DH_anon_WITH_RC4_128_MD5:
			return "DH_anon_WITH_RC4_128_MD5";
			break;
		case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
			return "DH_anon_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			return "DH_anon_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			return "DH_anon_WITH_AES_256_CBC_SHA256";
			break;

		/* Addendum from RFC 4279, TLS PSK */
		case TLS_PSK_WITH_RC4_128_SHA:
			return "PSK_WITH_RC4_128_SHA";
			break;
		case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
			return "PSK_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_PSK_WITH_AES_128_CBC_SHA:
			return "PSK_WITH_AES_128_CBC_SHA";
			break;
		case TLS_PSK_WITH_AES_256_CBC_SHA:
			return "PSK_WITH_AES_256_CBC_SHA";
			break;
		case TLS_DHE_PSK_WITH_RC4_128_SHA:
			return "DHE_PSK_WITH_RC4_128_SHA";
			break;
		case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
			return "DHE_PSK_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
			return "DHE_PSK_WITH_AES_128_CBC_SHA";
			break;
		case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
			return "DHE_PSK_WITH_AES_256_CBC_SHA";
			break;
		case TLS_RSA_PSK_WITH_RC4_128_SHA:
			return "RSA_PSK_WITH_RC4_128_SHA";
			break;
		case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
			return "RSA_PSK_WITH_3DES_EDE_CBC_SHA";
			break;
		case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
			return "RSA_PSK_WITH_AES_128_CBC_SHA";
			break;
		case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
			return "RSA_PSK_WITH_AES_256_CBC_SHA";
			break;

		/* RFC 4785 - Pre-Shared Key (PSK) Ciphersuites with NULL Encryption */
		case TLS_PSK_WITH_NULL_SHA:
			return "PSK_WITH_NULL_SHA";
			break;
		case TLS_DHE_PSK_WITH_NULL_SHA:
			return "DHE_PSK_WITH_NULL_SHA";
			break;
		case TLS_RSA_PSK_WITH_NULL_SHA:
			return "RSA_PSK_WITH_NULL_SHA";
			break;

		/*
		 * Addenda from rfc 5288 AES Galois Counter Mode (GCM) Cipher Suites
		 * for TLS.
		 */
		case TLS_RSA_WITH_AES_128_GCM_SHA256:
			return "RSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_RSA_WITH_AES_256_GCM_SHA384:
			return "RSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			return "DHE_RSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			return "DHE_RSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			return "DH_RSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			return "DH_RSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			return "DHE_DSS_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			return "DHE_DSS_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			return "DH_DSS_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			return "DH_DSS_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			return "DH_anon_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			return "DH_anon_WITH_AES_256_GCM_SHA384";
			break;

		/* RFC 5487 - PSK with SHA-256/384 and AES GCM */
		case TLS_PSK_WITH_AES_128_GCM_SHA256:
			return "PSK_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_PSK_WITH_AES_256_GCM_SHA384:
			return "PSK_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			return "DHE_PSK_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			return "DHE_PSK_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			return "RSA_PSK_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			return "RSA_PSK_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_PSK_WITH_AES_128_CBC_SHA256:
			return "PSK_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_PSK_WITH_AES_256_CBC_SHA384:
			return "PSK_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_PSK_WITH_NULL_SHA256:
			return "PSK_WITH_NULL_SHA256";
			break;
		case TLS_PSK_WITH_NULL_SHA384:
			return "PSK_WITH_NULL_SHA384";
			break;
		case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
			return "DHE_PSK_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
			return "DHE_PSK_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_DHE_PSK_WITH_NULL_SHA256:
			return "DHE_PSK_WITH_NULL_SHA256";
			break;
		case TLS_DHE_PSK_WITH_NULL_SHA384:
			return "DHE_PSK_WITH_NULL_SHA384";
			break;
		case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
			return "RSA_PSK_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
			return "RSA_PSK_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_RSA_PSK_WITH_NULL_SHA256:
			return "RSA_PSK_WITH_NULL_SHA256";
			break;
		case TLS_RSA_PSK_WITH_NULL_SHA384:
			return "RSA_PSK_WITH_NULL_SHA384";
			break;

		/*
		 * Addenda from rfc 5289  Elliptic Curve Cipher Suites with
		 * HMAC SHA-256/384.
		 */
		case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			return "ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			return "ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			return "ECDHE_RSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			return "ECDHE_RSA_WITH_AES_256_CBC_SHA384";
			break;
		case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			return "ECDH_RSA_WITH_AES_128_CBC_SHA256";
			break;
		case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			return "ECDH_RSA_WITH_AES_256_CBC_SHA384";
			break;

		/*
		 * Addenda from rfc 5289  Elliptic Curve Cipher Suites with
		 * SHA-256/384 and AES Galois Counter Mode (GCM)
		 */
		case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			return "ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			return "ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			return "ECDHE_RSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			return "ECDHE_RSA_WITH_AES_256_GCM_SHA384";
			break;
		case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			return "ECDH_RSA_WITH_AES_128_GCM_SHA256";
			break;
		case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			return "ECDH_RSA_WITH_AES_256_GCM_SHA384";
			break;

		default:
			break;
	}

	return NULL;
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
			case ENOENT:
				status =  errSSLClosedGraceful;
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
		//ereport(NOTICE, (errmsg("SSLSocketRead read: %d bytes", res)));
	}

	return status;
}

static OSStatus
SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len)
{
	OSStatus	status;
	int			res;
	Port	   *port = (Port *) conn;

	res = secure_raw_write(port, data, *len);

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

	//ereport(NOTICE, (errmsg("SSLSocketWrite wrote: %d bytes", res)));
	return status;
}

static UInt8 *
pem_to_der(const char *in, int *offset)
{
  char *sep_start, *sep_end, *cert_start, *cert_end;
  size_t i, j, err;
  size_t len;
  unsigned char *b64;

  /* Jump through the separators at the beginning of the certificate. */
  sep_start = strstr(in, "-----");
  if(sep_start == NULL)
    return NULL;
  cert_start = strstr(sep_start + 1, "-----");
  if(cert_start == NULL)
    return NULL;

  cert_start += 5;

  /* Find separator after the end of the certificate. */
  cert_end = strstr(cert_start, "-----");
  if(cert_end == NULL)
    return NULL;

  sep_end = strstr(cert_end + 1, "-----");
  if(sep_end == NULL)
    return NULL;
  sep_end += 5;

  len = cert_end - cert_start;
  b64 = palloc(len + 1);
  if(!b64)
    return NULL;

  /* Create base64 string without linefeeds. */
  for(i = 0, j = 0; i < len; i++) {
    if(cert_start[i] != '\r' && cert_start[i] != '\n')
      b64[j++] = cert_start[i];
  }
  b64[j] = '\0';

	UInt8 *out = palloc(len);	

  err = pg_b64_decode((const char *)b64, len, (char *) out);
  pfree(b64);

  *offset += sep_end - in;
  return out;
}

