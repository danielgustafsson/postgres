/*-------------------------------------------------------------------------
 *
 * be-secure-securetransport.c
 *	  Apple Secure Transport support
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * TODO:
 *		- Load DH keys from file
 *		- It would be good to be able to set "not applicable" on some options
 *		  like compression which isn't supported in Secure Transport (and most
 *		  likely any other SSL libraries supported in the future).
 *		- Support memory allocation in Secure Transport via a custom Core
 *		  Foundation allocator which is backed by a MemoryContext? Not sure it
 *		  would be possible but would be interested to investigate.
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
#include "utils/backend_random.h"
#include "utils/memutils.h"

/*
 * TODO: This dance is required due to collisions in the CoreFoundation
 * headers. How to handle it properly?
 */
#define pg_ACL_DELETE ACL_DELETE
#define pg_ACL_EXECUTE ACL_EXECUTE
#undef ACL_EXECUTE
#undef ACL_DELETE
#define Size pg_Size
#define uint64 pg_uint64
#define bool pg_bool
#include <Security/cssmerr.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#undef uint64
#undef bool
#undef Size
#undef ACL_DELETE
#undef ACL_EXECUTE
#define pg_uint64 uint64
#define pg_bool bool
#define pg_Size Size
#define ACL_DELETE pg_ACL_DELETE
#define ACL_EXECUTE pg_ACL_EXECUTE

#ifndef errSecUnknownFormat
#define errSecUnknownFormat -25257
#endif

/* ------------------------------------------------------------ */
/*				Struct definitions and Static variables			*/
/* ------------------------------------------------------------ */

/*
 * For Secure Transport API functions we rely on SecCopyErrorMessageString()
 * which will provide a human readable error message for the individual error
 * statuses. For our static functions, we mimic the behaviour by passing
 * errSecInternalError and setting the error message in internal_err.
 */
#define ERR_MSG_LEN 128
static char internal_err[ERR_MSG_LEN];

/* ------------------------------------------------------------ */
/*							Prototypes							*/
/* ------------------------------------------------------------ */

extern SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator,
										SecCertificateRef certificate,
										SecKeyRef privateKey);

static OSStatus load_certificate(char *name, CFArrayRef *cert_array);
static void load_key(char *name, CFArrayRef *out);

static char * pg_SSLerrmessage(OSStatus status);
static OSStatus pg_SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len);
static OSStatus pg_SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len);

/* src/backend/libpq/securetransport_common.c */
extern const char * SSLciphername(SSLCipherSuite cipher);

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

int
be_tls_init(bool isServerStart)
{
	memset(internal_err, '\0', sizeof(internal_err));

	/*
	 * This is where we'd like to load and parse certificates and private keys
	 * for the connection, but since Secure Transport will spawn threads deep
	 * inside the API we must postpone this until inside a backend. This means
	 * that we won't fail on an incorrect certificate chain until a connection
	 * is attempted, unlike with OpenSSL where we fail immediately on server
	 * startup.
	 */

	return 0;
}

/*
 * be_tls_destroy
 *		Tear down global Secure Transport structures and return resources.
 */
void
be_tls_destroy(void)
{
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
	SecIdentityRef		identity;
	CFArrayRef			root_certificates;
	CFArrayRef			certificates;
	CFArrayRef			keys;
	CFMutableArrayRef	chain;

	Assert(!port->ssl);

	status = load_certificate(ssl_cert_file, &certificates);
	if (status != noErr)
		ereport(COMMERROR,
				(errmsg("could not load server certificate \"%s\": \"%s\"",
						ssl_cert_file, pg_SSLerrmessage(status))));

	load_key(ssl_key_file, &keys);

	/*
	 * We now have a certificate and either a private key, or a search path
	 * which should contain it.
	 */
	identity = SecIdentityCreate(NULL,
								 (SecCertificateRef) CFArrayGetValueAtIndex(certificates, 0),
								 (SecKeyRef) CFArrayGetValueAtIndex(keys, 0));
	if (identity == NULL)
		ereport(COMMERROR,
				(errmsg("could not create identity: \"%s\"",
				 pg_SSLerrmessage(status))));

	/*
	 * SSLSetCertificate() sets the certificate(s) to use for the connection.
	 * The first element in the passed array is required to be the identity
	 * with elements 1..n being certificates.
	 */
	chain = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	CFRetain(identity);
	CFArrayInsertValueAtIndex(chain, 0, identity);
	CFArrayAppendArray(chain, certificates,
					   CFRangeMake(0, CFArrayGetCount(certificates)));

	/*
	 * Load the Certificate Authority if configured
	 */
	if (ssl_ca_file[0])
	{
		status = load_certificate(ssl_ca_file, &root_certificates);
		if (status == noErr)
		{
			CFArrayAppendArray(chain, root_certificates,
							   CFRangeMake(0, CFArrayGetCount(root_certificates)));

			ssl_loaded_verify_locations = true;
		}
		else
		{
			ereport(LOG,
					(errmsg("could not load root certificate \"%s\": \"%s\"",
					 ssl_ca_file, pg_SSLerrmessage(status))));

			ssl_loaded_verify_locations = false;
		}
	}
	else
		ssl_loaded_verify_locations = false;

	/*
	 * Certificate Revocation List are not supported in the Secure Transport
	 * API
	 */
	if (ssl_crl_file[0])
		ereport(FATAL,
				(errmsg("CRL files not supported with Secure Transport")));

	port->ssl = (void *) SSLCreateContext(NULL, kSSLServerSide, kSSLStreamType);
	if (!port->ssl)
		ereport(COMMERROR,
				(errmsg("could not create SSL context")));

	port->ssl_in_use = true;
	port->ssl_buffered = 0;

	/*
	 * We use kTryAuthenticate here since we don't know which sslmode the
	 * client is using. If we were to use kAlwaysAuthenticate then sslmode
	 * require won't work as intended.
	 */
	if (ssl_loaded_verify_locations)
		SSLSetClientSideAuthenticate((SSLContextRef) port->ssl, kTryAuthenticate);

	/*
	 * TODO: This loads a pregenerated DH parameter, code for loading DH from a
	 * specified file needs to be added. In Secure Transport, DH is always on
	 * an in case no parameter has been loaded one with be precomputed
	 * automatically, so that step is not required to be added. This is of
	 * course the one step we want to avoid since it consumes a lot of time.
	 */
	SSLSetDiffieHellmanParams((SSLContextRef) port->ssl,
							  file_dh2048, sizeof(file_dh2048));

	/*
	 * SSLSetProtocolVersionEnabled() is marked as deprecated as of 10.9
	 * but the alternative SSLSetSessionConfig() is as of 10.11 not yet
	 * documented with the kSSLSessionConfig_xxx constants belonging to
	 * the 10.12 SDK. Rely on the deprecated version for now until the
	 * dust has properly settled around this.
	 */
	SSLSetProtocolVersionEnabled((SSLContextRef) port->ssl, kTLSProtocol12, true);

	status = SSLSetCertificate((SSLContextRef) port->ssl,
							   (CFArrayRef) chain);
	if (status != noErr)
		ereport(COMMERROR,
				(errmsg("could not set certificate for connection: \"%s\"",
				 pg_SSLerrmessage(status))));

	status = SSLSetIOFuncs((SSLContextRef) port->ssl,
						   pg_SSLSocketRead,
						   pg_SSLSocketWrite);
	if (status != noErr)
		ereport(COMMERROR,
				(errmsg("could not set SSL IO functions: \"%s\"",
				 pg_SSLerrmessage(status))));

	status = SSLSetSessionOption((SSLContextRef) port->ssl,
								 kSSLSessionOptionBreakOnClientAuth, true);
	if (status != noErr)
		ereport(COMMERROR,
				(errmsg("could not set SSL certificate validation: \"%s\"",
				 pg_SSLerrmessage(status))));

	status = SSLSetConnection((SSLContextRef) port->ssl, port);
	if (status != noErr)
		ereport(COMMERROR,
				(errmsg("could not establish SSL connection: \"%s\"",
				 pg_SSLerrmessage(status))));

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

		if (status == errSSLPeerAuthCompleted)
		{
			status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
			if (status != noErr || trust == NULL)
			{
				ereport(WARNING,
					(errmsg("SSLCopyPeerTrust returned: \"%s\"",
					 pg_SSLerrmessage(status))));
				port->peer_cert_valid = false;
				return 0;
			}

			if (ssl_loaded_verify_locations)
			{
				status = SecTrustSetAnchorCertificates(trust, root_certificates);
				if (status != noErr)
				{
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificates returned: \"%s\"",
						 pg_SSLerrmessage(status))));
					return -1;
				}

				status = SecTrustSetAnchorCertificatesOnly(trust, false);
				if (status != noErr)
				{
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificatesOnly returned: \"%s\"",
						 pg_SSLerrmessage(status))));
					return -1;
				}
			}

			status = SecTrustEvaluate(trust, &trust_eval);
			if (status != noErr)
			{
				ereport(WARNING,
					(errmsg("SecTrustEvaluate failed, returned: \"%s\"",
					 pg_SSLerrmessage(status))));
				return -1;
			}

			switch (trust_eval)
			{
				/*
				 * If 'Unspecified' then an anchor certificate was reached
				 * without encountering any explicit user trust. If 'Proceed'
				 * then the user has chosen to explicitly trust a certificate
				 * in the chain by clicking "Trust" in the Keychain app.
				 */
				case kSecTrustResultUnspecified:
				case kSecTrustResultProceed:
					port->peer_cert_valid = true;
					break;

				/*
				 * 'Confirm' indicates that an interactive confirmation from
				 * the user is requested. This result code was deprecated in
				 * 10.9 however so treat it as a Deny to avoid having to invoke
				 * UI elements from the Keychain.
				 */
				case kSecTrustResultConfirm:
					port->peer_cert_valid = true;
					break;

				/*
				 * 'RecoverableTrustFailure' indicates that the certificate was
				 * rejected but might be trusted with minor changes to the eval
				 * context (ignoring expired certificate etc). In the frontend
				 * we can in some circumstances allow this, but in the backend
				 * this always means that the client certificate is considered
				 * untrusted.
				 */
				case kSecTrustResultRecoverableTrustFailure:
					port->peer_cert_valid = false;
					break;

				/*
				 * Treat all other cases as rejection without further
				 * questioning.
				 */
				default:
					port->peer_cert_valid = false;
					break;
			}

			if (port->peer_cert_valid)
			{
				SecCertificateRef usercert = SecTrustGetCertificateAtIndex(trust, 0L);

				CFStringRef usercert_cn;
				SecCertificateCopyCommonName(usercert, &usercert_cn);
				port->peer_cn = pstrdup(CFStringGetCStringPtr(usercert_cn, kCFStringEncodingUTF8));

				CFRelease(usercert_cn);
			}

			CFRelease(trust);
		}
	}

	if (status != noErr)
		return -1;

	return 0;
}

/*
 *	load_key
 *		Extracts a key from a PEM file on the filesystem
 *
 * Loads a private key from the specified filename. Unless the key loads this
 * will not return but will error out.
 */
static void
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
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not load private key \"%s\": unable to stat",
						name)));

	if (!S_ISREG(stat_buf.st_mode))
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not load private key \"%s\": not a regular file",
						name)));

	/*
	 * Require no public access to the key file. If the file is owned by us,
	 * require mode 0600 or less. If owned by root, require 0640 or less to
	 * allow read access through our gid, or a supplementary gid that allows to
	 * read system-wide certificates.
	 */
	if ((stat_buf.st_uid == geteuid() && stat_buf.st_mode & (S_IRWXG | S_IRWXO)) ||
		(stat_buf.st_uid == 0 && stat_buf.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)))
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("private key file \"%s\" has group or world access",
						name),
				 errdetail("File must have permissions u=rw (0600) or less "
						   "if owned by the database user, or permissions "
						   "u=rw,g=r (0640) or less if owned by root.")));

	if ((fd = AllocateFile(name, "r")) == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not load private key \"%s\": unable to open",
						name)));

	buf = palloc(stat_buf.st_size);

	ret = fread(buf, 1, stat_buf.st_size, fd);
	FreeFile(fd);

	if (ret != stat_buf.st_size)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not load private key \"%s\": unable to read",
						name)));

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

	if (status != noErr)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("could not load private key \"%s\": \"%s\"",
						name, pg_SSLerrmessage(status))));
}

/*
 *	load_certificate
 *		Extracts a certificate from a PEM file on the filesystem
 *
 * TODO: figure out better returncodes
 */
static OSStatus
load_certificate(char *name, CFArrayRef *cert_array)
{
	struct stat			stat_buf;
	int					ret;
	UInt8			   *buf;
	FILE			   *fd;
	CFDataRef			data;
	SecExternalFormat	format;
	SecExternalItemType	type;
	CFStringRef			path;
	OSStatus			status;

	/*
	 * If the configured ssl_cert_file filename is set to a non-existing
	 * file, assume it's referencing a Keychain label and attempt to load
	 * the certificate from the Keychain instead.
	 */
	ret = stat(name, &stat_buf);
	if (ret != 0 && errno == ENOENT)
	{
		/*
		 * TODO: Do we want to search keychains for certificates serverside
		 * like we do clientside, or do we want to stick to a single way to
		 * configure the server? Since CRL files aren't supported outside
		 * keychains I guess we need to, but worth a discussion.
		 */
		return errSecInternalError;
	}
	else if (ret == 0 && S_ISREG(stat_buf.st_mode))
	{
		if ((fd = AllocateFile(name, "r")) == NULL)
			return errSecInternalError;

		buf = palloc(stat_buf.st_size);
		ret = fread(buf, 1, stat_buf.st_size, fd);
		FreeFile(fd);

		if (ret != stat_buf.st_size)
			return errSecInternalError;

		type = kSecItemTypeCertificate;
		format = kSecFormatPEMSequence;
		path = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
		data = CFDataCreate(NULL, buf, stat_buf.st_size);

		status = SecItemImport(data, path, &format, &type, 0, NULL, NULL, cert_array);
		pfree(buf);

		return status;
	}

	return errSecInternalError;
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
						pg_SSLerrmessage(ssl_status))));

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
	OSStatus		status;
	SSLProtocol		protocol;

	if (ptr == NULL || len == 0)
		return;

	ptr[0] = '\0';

	if (!(SSLContextRef) port->ssl)
		return;

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
				strlcpy(ptr, "unknown", len);
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
		 * If the connection was closed for an unforeseen reason, return error
		 * and set errno such that the caller can raise an appropriate ereport
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
							pg_SSLerrmessage(read_status))));
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

	/*
	 * SSLWrite returns the number of bytes written in the 'n' argument. This
	 * however can be data either actually written to the socket, or buffered
	 * in the context. In the latter case SSLWrite will return errSSLWouldBlock
	 * and we need to call it with no new data (NULL) to drain the buffer on to
	 * the socket. We track the buffer in ssl_buffered and clear that when all
	 * data has been drained.
	 */
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

			/*
			 * The data was buffered in the context rather than written to the
			 * socket. Track this and repeatedly call SSLWrite to drain the
			 * buffer. See comment above.
			 */
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

			/* Clean disconnections */
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

int
be_tls_get_cipher_bits(Port *port)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	SecKeyRef			key;
	int					keysize = 0;

	if (!(SSLContextRef) port->ssl)
		return 0;

	status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
	if (status == noErr)
	{
		cert = SecTrustGetCertificateAtIndex(trust, 0);
		status = SecCertificateCopyPublicKey(cert, &key);
		if (status == noErr)
		{
			keysize = SecKeyGetBlockSize(key);
			CFRelease(key);
		}
	}

	CFRelease(trust);
	return keysize;
}

void
be_tls_get_peerdn_name(Port *port, char *ptr, size_t len)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	CFStringRef			dn_str;

	if (!ptr || len == 0)
		return;

	ptr[0] = '\0';

	if (!(SSLContextRef) port->ssl)
		return;

	status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
	if (status == noErr)
	{
		/*
		 * TODO: copy the certificate parts with SecCertificateCopyValues and
		 * parse the OIDs to build up the DN
		 */
		cert = SecTrustGetCertificateAtIndex(trust, 0);
		dn_str = SecCertificateCopyLongDescription(NULL, cert, NULL);
		if (dn_str)
		{
			strlcpy(ptr, CFStringGetCStringPtr(dn_str, kCFStringEncodingASCII), len);
			CFRelease(dn_str);
		}

		CFRelease(trust);
	}
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

	if (!ptr || len == 0)
		return;

	ptr[0] = '\0';

	if (!(SSLContextRef) port->ssl)
		return;

	status = SSLGetNegotiatedCipher((SSLContextRef) port->ssl, &cipher);
	if (status != noErr)
		return;

	cipher_name = SSLciphername(cipher);
	if (cipher_name != NULL)
		strlcpy(ptr, cipher_name, len);
}

/*
 * be_tls_get_compression
 *		Retrieve and return whether compression is used for the	current
 *		connection.
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
 * pg_SSLerrmessage
 *		Create and return a human readable error message given
 *		the specified status code
 *
 * While only interesting to use for error cases, the function will return a
 * translation for non-error statuses as well like noErr and errSecSuccess.
 */
static char *
pg_SSLerrmessage(OSStatus status)
{
	CFStringRef		err_msg;
	char		   *err_buf;

	/*
	 * While errSecUnknownFormat has been defined as -25257 at least since 10.8
	 * Lion, there still is no translation for it in 10.11 El Capitan, so we
	 * maintain our own
	 */
	if (status == errSecUnknownFormat)
		return pstrdup(_("The item you are trying to import has an unknown format."));

	/*
	 * If the error is internal, and we have an error message in the internal
	 * buffer, then return that error and clear the internal buffer.
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
			err_buf = pstrdup(CFStringGetCStringPtr(err_msg,
													kCFStringEncodingUTF8));
			CFRelease(err_msg);
		}
		else
			err_buf = pstrdup(_("unknown SSL error"));
	}

	return err_buf;
}

/* ------------------------------------------------------------ */
/*				Internal functions - Socket IO					*/
/* ------------------------------------------------------------ */

/*
 *	pg_SSLSocketRead
 *
 * Callback for reading data from the connection. When entering the function,
 * len is set to the number of bytes requested. Upon leaving, len should be
 * overwritten with the actual number of bytes read.
 */
static OSStatus
pg_SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len)
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
	}

	return status;
}

static OSStatus
pg_SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len)
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

	return status;
}
