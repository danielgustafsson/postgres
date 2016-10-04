/*-------------------------------------------------------------------------
 *
 * fe-secure-securetransport.c
 *	  Secure Transport support
 *
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/interfaces/libpq/fe-secure-securetransport.c
 *
 * NOTES
 *	  Unlike the OpenSSL support there is no shared state between connections
 *	  so there is no special handling for ENABLE_THREAD_SAFETY.
 *
 * TODO:
 *		- CRL support
 *			- CRL is handled by the Keychain and there is no (obvious) way to
 *			  inject x509 CRL records programatically. Perhaps creating a temp
 *			  keychain for the connection and see if we can manipulate that?
 *		- Load certificate/key from keychain
 *			- Currently the certificate/key are expected to be files on disk
 *			  but with a good prefix like keychain:foo we can load directly
 *			  from the keychain the user wants.
 *		- Supprt pkcs12 certificates
 *		- Remove use of private API
 *		- Remove use of deprecated functions
 *		- pgcrypto
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <signal.h>
#include <fcntl.h>
#include <ctype.h>

#include "libpq-fe.h"
#include "fe-auth.h"
#include "libpq-int.h"

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>

#include <sys/stat.h>

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>

/*
 * The number of required key/value pairs in the dictionary used for querying
 * the Keychain: Class, Return Reference, MatchLimit, MatchPolicy
 */
#define KEYCHAIN_SEARCH_SIZE 4

/*
 * Private API call used in the Webkit code for creating an identity from a
 * certificate with a key. While stable and used in many open source projects
 * it should be replaced with a published API call since private APIs aren't
 * subject to the same deprecation rules. Could potentially be replaced by
 * using SecIdentityCreateWithCertificate() ?
 */
extern SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator,
										SecCertificateRef certificate,
										SecKeyRef privateKey);

static char *SSLerrmessage(OSStatus errcode);
static void SSLerrfree(char *err_buf);
static int SSLsessionstate(PGconn *conn, char *msg, size_t len);
static const char * SSLciphername(SSLCipherSuite cipher);

static OSStatus SSLSocketRead(SSLConnectionRef conn, void *data,
							  size_t *len);
static OSStatus SSLSocketWrite(SSLConnectionRef conn, const void *data,
							   size_t *len);
static OSStatus SSLOpenClient(PGconn *conn);
static OSStatus SSLLoadCertificate(PGconn *conn, CFArrayRef *cert_array,
								   CFArrayRef *key_array,
								   CFArrayRef *rootcert_array);

static OSStatus import_certificate(const char *path, int size,
								   SecExternalFormat format, char *passphrase,
								   CFArrayRef *certificate);
static OSStatus import_pem(const char *path, int size, char *passphrase,
						   CFArrayRef *cert_arr);
static OSStatus import_pkcs12(const char *path, int size, char *passphrase,
							  CFArrayRef *cert_arr);

/* ------------------------------------------------------------ */
/*						 Public interface						*/
/* ------------------------------------------------------------ */

/*
 *	Exported function to allow application to tell us it's already
 *	initialized Secure Transport and/or libcrypto.
 */
void
pgtls_init_library(bool do_ssl, int do_crypto)
{
#ifndef __darwin__
	/*
	 * Secure Transport is only available on Darwin platforms so autoconf
	 * should protect us from ever reaching here
	 */
	Assert(false);
#endif
}

/*
 *	Begin or continue negotiating a secure session.
 */
PostgresPollingStatusType
pgtls_open_client(PGconn *conn)
{
	OSStatus open_status;

	CFArrayRef certificate;
	CFArrayRef key;
	CFArrayRef rootcert;

	/*
	 * If the SSL context hasn't been set up then initiate it, else continue
	 * with handshake
	 */
	if (conn->ssl == NULL)
	{
		conn->ssl_key_bits = 0;
		conn->ssl_buffered = 0;
		/*
		 * Create the SSL context using the new API introduced in 10.8 since
		 * the SSLNewContext() API call was deprecated in 10.9. The standard
		 * allocator is used since we are client side.
		 */
		conn->ssl = SSLCreateContext(NULL /* allocator */,
									 kSSLClientSide, kSSLStreamType);
		if (!conn->ssl)
		{
			printfPQExpBuffer(&conn->errorMessage,
				   libpq_gettext("could not create SSL context\n"));
			return PGRES_POLLING_FAILED;
		}

		/*
		 * SSLSetProtocolVersionEnabled() is marked as deprecated as of 10.9
		 * but the alternative SSLSetSessionConfig() is as of 10.11 not yet
		 * documented with the kSSLSessionConfig_xxx constants belonging to
		 * the 10.12 SDK. Rely on the deprecation for now until the dust has
		 * properly settled around this.
		 */
		SSLSetProtocolVersionEnabled(conn->ssl, kTLSProtocol12, true);

		open_status = SSLSetConnection(conn->ssl, conn);
		if (open_status != noErr)
			goto error;

		/*
		 * Set the low level functions for reading and writing off a socket
		 */
		open_status = SSLSetIOFuncs(conn->ssl, SSLSocketRead, SSLSocketWrite);
		if (open_status != noErr)
			goto error;

		/*
		 * Load client certificate, private key, and trusted CA certs. The
		 * conn->errorMessage will be populated by the certificate loading
		 * so we can return without altering it.
		 */
		if (SSLLoadCertificate(conn, &certificate, &key, &rootcert) != noErr)
		{
			pgtls_close(conn);
			return PGRES_POLLING_FAILED;
		}

		conn->st_rootcert = (void *) CFRetain(rootcert);

		/*
		 * If we are asked to verify the peer hostname, set it as a requirement
		 * on the connection. This must be set before calling SSLHandshake().
		 */
		if (strcmp(conn->sslmode, "verify-full") == 0)
		{
			/* If we are asked to verify a hostname we dont have, error out */
			if (!conn->pghost)
			{
				pgtls_close(conn);
				return PGRES_POLLING_FAILED;
			}

			SSLSetPeerDomainName(conn->ssl, conn->pghost, strlen(conn->pghost));
		}
	}

	/*
	 * Perform handshake
	 */
	open_status = SSLOpenClient(conn);
	if (open_status == noErr)
	{
		conn->ssl_in_use = true;
		return PGRES_POLLING_OK;
	}

error:
	if (open_status != noErr)
	{
		char *err_msg = SSLerrmessage(open_status);
		if (conn->errorMessage.len > 0)
			appendPQExpBuffer(&conn->errorMessage,
							  libpq_gettext(", ssl error: %s\n"), err_msg);
		else
			printfPQExpBuffer(&conn->errorMessage,
							  libpq_gettext("could not establish SSL connection: %s\n"),
									err_msg);
		SSLerrfree(err_msg);

		pgtls_close(conn);
	}

	return PGRES_POLLING_FAILED;
}

/*
 * SSLOpenClient
 *		Validates remote certificate and performs handshake.
 *
 * If the user has supplied a root certificate we add that to the chain here
 * before initiating validation. The caller is responsible for invoking error
 * logging in the case of errors returned.
 */
static OSStatus
SSLOpenClient(PGconn *conn)
{
	OSStatus			status;
	SecTrustRef			trust = NULL;
	SecTrustResultType	trust_eval = 0;
	bool				trusted = false;
	bool				only_anchor = true;

	SSLSetSessionOption(conn->ssl, kSSLSessionOptionBreakOnServerAuth, true);

	/*
	 * TODO: Is there a better way to repeatedly call SSLHandshake until we get
	 * another response than an errSSLWouldBlock?
	 */
	do
	{
		status = SSLHandshake(conn->ssl);
		/* busy-wait loop */
	}
	while (status == errSSLWouldBlock || status == -1);

	if (status != errSSLServerAuthCompleted)
		return status;

	/*
	 * Get peer server certificate and validate it. SSLCopyPeerTrust() is not
	 * supposed to return a NULL trust on noErr but have been reported to do
	 * in the past so add a belts-and-suspenders check
	 */
	status = SSLCopyPeerTrust(conn->ssl, &trust);
	if (status != noErr || trust == NULL)
		return status;

	/*
	 * If we have our own root certificate configured then add it to the chain
	 * of trust and specify that it should be trusted.
	 */
	if (conn->st_rootcert)
	{
		status = SecTrustSetAnchorCertificates(trust, (CFArrayRef) conn->st_rootcert);
		if (status != noErr)
			return status;

		/* We have a trusted local root cert, trust more than anchor */
		only_anchor = false;
	}

	status = SecTrustSetAnchorCertificatesOnly(trust, only_anchor);
	if (status != noErr)
		return status;

	status = SecTrustEvaluate(trust, &trust_eval);
	if (status == errSecSuccess)
	{
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
				trusted = true;
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
			/*
			 * The below results are all cases where the certificate should be
			 * rejected without further questioning.
			 */
			case kSecTrustResultDeny:
			case kSecTrustResultFatalTrustFailure:
			case kSecTrustResultOtherError:
			default:
				trusted = false;
				break;
		}
	}

	/*
	 * TODO: return a better error code than SSLInternalError
	 */
	if (!trusted)
		return errSecInternalError;

	/*
	 * If we reach here the documentation states we need to run the Handshake
	 * again after validating the trust
	 */
	return SSLOpenClient(conn);
}

/*
 *	Is there unread data waiting in the SSL read buffer?
 */
bool
pgtls_read_pending(PGconn *conn)
{
	OSStatus read_status;
	size_t len = 0;

	read_status = SSLGetBufferedReadSize(conn->ssl, &len);

	/*
	 * Should we get an error back then we assume that subsequent read
	 * operations will fail as well.
	 */
	return (read_status == noErr && len > 0);
}

/*
 *  pgtls_read
 *	    Read data from a secure connection.
 *
 * On failure, this function is responsible for putting a suitable message
 * into conn->errorMessage.  The caller must still inspect errno, but only
 * to determine whether to continue/retry after error.
 */
ssize_t
pgtls_read(PGconn *conn, void *ptr, size_t len)
{
	OSStatus	read_status;
	size_t		n = 0;
	ssize_t		ret = 0;
	int			read_errno = 0;
	char		sess_msg[25];

	/*
	 * Double-check that we have a connection which is in the correct state
	 * for reading before attempting to pull any data off the wire.
	 */
	if (SSLsessionstate(conn, sess_msg, sizeof(sess_msg)) == -1)
	{
		printfPQExpBuffer(&conn->errorMessage,
			libpq_gettext("SSL connection is: %s\n"), sess_msg);
		read_errno = ECONNRESET;
		return -1;
	}

	read_status = SSLRead(conn->ssl, ptr, len, &n);
	ret = (ssize_t) n;

	switch (read_status)
	{
		case noErr:
			break;
		case -1:
		case errSSLWouldBlock:
			/* If we did perform a read then skip EAGAIN */
			if (n == 0)
				read_errno = EINTR;
			break;

		/*
		 * Clean disconnections
		 */
		case errSSLClosedNoNotify:
			/* fall through */
		case errSSLClosedGraceful:
			printfPQExpBuffer(&conn->errorMessage,
				libpq_gettext("SSL connection has been closed unexpectedly\n"));
			read_errno = ECONNRESET;
			ret = -1;
			break;

		default:
			printfPQExpBuffer(&conn->errorMessage,
				libpq_gettext("unrecognized SSL error %d\n"), read_status);
			read_errno = ECONNRESET;
			ret = -1;
			break;
	}

	SOCK_ERRNO_SET(read_errno);
	return ret;
}

/*
 *	Write data to a secure connection.
 *
 * On failure, this function is responsible for putting a suitable message
 * into conn->errorMessage.  The caller must still inspect errno, but only
 * to determine whether to continue/retry after error.
 */
ssize_t
pgtls_write(PGconn *conn, const void *ptr, size_t len)
{
	OSStatus	write_status;
	size_t		n = 0;
	ssize_t		ret = 0;
	int			write_errno = 0;
	char		sess_msg[25];

	/*
	 * Double-check that we have a connection which is in the correct state
	 * for writing before attempting to push any data on to the wire or the
	 * local SSL buffer.
	 */
	if (SSLsessionstate(conn, sess_msg, sizeof(sess_msg)) == -1)
	{
		printfPQExpBuffer(&conn->errorMessage,
			libpq_gettext("SSL connection is: %s\n"), sess_msg);
		write_errno = ECONNRESET;
		return -1;
	}

	if (conn->ssl_buffered > 0)
	{
		write_status = SSLWrite(conn->ssl, NULL, 0, &n);

		if (write_status == noErr)
		{
			ret = conn->ssl_buffered;
			conn->ssl_buffered = 0;
		}
		else if (write_status == errSSLWouldBlock || write_status == -1)
		{
			ret = 0;
			write_errno = EINTR;
		}
		else
		{
			/* TODO: pull error message string, on read too */
			printfPQExpBuffer(&conn->errorMessage,
				libpq_gettext("unrecognized SSL error: %d\n"), write_status);
			ret = -1;
			write_errno = ECONNRESET;
		}
	}
	else
	{
		write_status = SSLWrite(conn->ssl, ptr, len, &n);
		ret = n;

		switch (write_status)
		{
			case noErr:
				break;

			case -1:
			case errSSLWouldBlock:
				conn->ssl_buffered = len;
				ret = 0;
#ifdef EAGAIN
				write_errno = EAGAIN;
#else
				write_errno = EINTR;
#endif
				break;

			/*
			 * Clean disconnections
		 	*/
			case errSSLClosedNoNotify:
				/* fall through */
			case errSSLClosedGraceful:
				printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("SSL connection has been closed unexpectedly\n"));
				write_errno = ECONNRESET;
				ret = -1;
				break;

			default:
				printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("unrecognized SSL error %d\n"), write_status);
				write_errno = ECONNRESET;
				ret = -1;
				break;
		}
	}

	SOCK_ERRNO_SET(write_errno);
	return ret;
}

/*
 * Initialize SSL system, in particular creating the SSL_context object
 * that will be shared by all SSL-using connections in this process.
 *
 * In threadsafe mode, this includes setting up libcrypto callback functions
 * to do thread locking.
 *
 * If the caller has told us (through PQinitOpenSSL) that he's taking care
 * of libcrypto, we expect that callbacks are already set, and won't try to
 * override it.
 *
 * The conn parameter is only used to be able to pass back an error
 * message - no connection-local setup is made here.
 *
 * Returns 0 if OK, -1 on failure (with a message in conn->errorMessage).
 */
int
pgtls_init(PGconn *conn)
{
	conn->ssl_buffered = 0;
	conn->ssl_in_use = false;

	return 0;
}

/*
 *  pgtls_close
 *	    Close SSL connection.
 *
 * This function must cope with connections in all states of disrepair since
 * it will be called from pgtls_open_client to clean up any potentially used
 * resources in case it breaks halfway.
 */
void
pgtls_close(PGconn *conn)
{
	if (!conn->ssl)
		return;

	CFRelease((CFArrayRef) conn->st_rootcert);

	SSLClose(conn->ssl);
	CFRelease(conn->ssl);

	/* TODO: Release any certificates loaded */

	conn->ssl = NULL;
	conn->ssl_in_use = false;
}



/*
 * The amount of read bytes is returned in the len variable
 */
static OSStatus
SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len)
{
	OSStatus	status = noErr;
	int			res;

	res = pqsecure_raw_read((PGconn *) conn, data, *len);

	if (res < 0)
	{
		/* TODO: Handle more error cases? */
		switch (SOCK_ERRNO)
		{
			case ENOENT:
				status = errSSLClosedGraceful;
				break;

#ifdef EAGAIN
			case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
			case EWOULDBLOCK:
#endif
			case EINTR:
				status = errSSLWouldBlock;
				break;
		}

		*len = 0;
	}
	else
		*len = res;

	return status;
}

static OSStatus
SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len)
{
	OSStatus	status = noErr;
	int			res;

	res = pqsecure_raw_write((PGconn *) conn, data, *len);

	if (res < 0)
	{
		/* TODO: Handle more error cases? */
		switch (SOCK_ERRNO)
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
				break;
		}
	}

	*len = res;

	return status;
}

static OSStatus
import_pem(const char *path, int size, char *passphrase, CFArrayRef *cert_arr)
{
	return import_certificate(path, size, kSecFormatPEMSequence, passphrase, cert_arr);
}

static OSStatus
import_pkcs12(const char *path, int size, char *passphrase, CFArrayRef *cert_arr)
{
	return import_certificate(path, size, kSecFormatPKCS12, passphrase, cert_arr);
}

/*
 * import_certificate_keychain
 *
 * Queries the local keychain for a certificate with the passed identity.
 */
static OSStatus
import_certificate_keychain(const char *identity, SecIdentityRef *certificate)
{
	OSStatus		status = errSecItemNotFound;
	CFTypeRef		key[KEYCHAIN_SEARCH_SIZE];
	CFTypeRef		val[KEYCHAIN_SEARCH_SIZE];
	CFDictionaryRef	identity_search;
	CFStringRef		identity_ref;

	identity_ref = CFStringCreateWithCString(NULL /* allocator */,
											 identity, kCFStringEncodingUTF8);
	key[0] = kSecClass;
	val[0] = kSecClassIdentity;
	key[1] = kSecReturnRef;
	val[1] = kCFBooleanTrue;
	key[2] = kSecMatchLimit;
	val[2] = kSecMatchLimitOne;
	key[3] = kSecMatchPolicy;
	val[3] = SecPolicyCreateSSL(false, identity_ref);

	identity_search = CFDictionaryCreate(NULL /* allocator */,
										 (const void **) key,
										 (const void **) val,
										 KEYCHAIN_SEARCH_SIZE,
										 &kCFCopyStringDictionaryKeyCallBacks,
										 &kCFTypeDictionaryValueCallBacks);

	status = SecItemCopyMatching(identity_search, (CFTypeRef *) certificate);

	CFRelease(identity_search);
	CFRelease(val[3]);
	CFRelease(identity_ref);

	return status;
}

static OSStatus
import_certificate(const char *path, int size, SecExternalFormat format,
				   char *passphrase, CFArrayRef *certificate)
{
	OSStatus							status;
	CFDataRef							data_ref;
	CFStringRef							file_type;
	SecExternalItemType					item_type;
	SecItemImportExportKeyParameters	params;

	FILE *fp;
	UInt8 *certdata;

	Assert(path && strlen(path) > 0);

	fp = fopen(path, "r");
	if (!fp)
		return errSecInternalError;

	certdata = malloc(size);
	if (!certdata)
	{
		fclose(fp);
		return errSecAllocate;
	}

	/* TODO: should we use fopen()/fread() here or other fs abstractions */
	if (fread(certdata, 1, size, fp) != size)
	{
		fclose(fp);
		return errSecInternalError;
	}
	fclose(fp);

	data_ref = CFDataCreate(NULL /* allocator */, certdata, size);

	memset(&params, 0, sizeof(SecItemImportExportKeyParameters));
	params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	/* Set OS default access control on the imported key */
	params.flags = kSecKeyNoAccessControl;
	if (passphrase)
		params.passphrase = CFStringCreateWithCString(NULL, passphrase,
													  kCFStringEncodingUTF8);

	/*
	 * Provide a synthetic file ending for the certificate file to aid the
	 * parsing of the certificate, the default name of ".crt" isn't terribly
	 * helpful for figuring out the type
	 */
	if (format == kSecFormatPKCS12)
		file_type = CFSTR(".pkcs12");
	else
		file_type = CFSTR(".pem");

	item_type = kSecItemTypeCertificate;

	status = SecItemImport(data_ref, file_type, &format, &item_type,
						   0 /* flags */, &params, NULL /* keychain */,
						   certificate);

	return status;
}

/*
 * Since failures can come from multiple places, the PGconn errorMessage is
 * populated here even for SSL library errors.
 */
static OSStatus
SSLLoadCertificate(PGconn *conn, CFArrayRef *cert_array, CFArrayRef *key_array,
				   CFArrayRef *rootcert_array)
{
	OSStatus			status;
	struct stat 		buf;
	char				homedir[MAXPGPATH];
	char				fnbuf[MAXPGPATH];
	char				sebuf[256];
	bool				have_homedir;
	bool				have_cert;
	char	   		   *ssl_err_msg;
	CFMutableArrayRef	cert_copy;
	SecIdentityRef		identity;
	SecCertificateRef	cert_ref;
	SecKeyRef			key_ref;

	/*
	 * We'll need the home directory if any of the relevant parameters are
	 * defaulted.  If pqGetHomeDirectory fails, act as though none of the
	 * files could be found.
	 */
	if (!(conn->sslcert && strlen(conn->sslcert) > 0) ||
		!(conn->sslkey && strlen(conn->sslkey) > 0) ||
		!(conn->sslrootcert && strlen(conn->sslrootcert) > 0) ||
		!(conn->sslcrl && strlen(conn->sslcrl) > 0))
		have_homedir = pqGetHomeDirectory(homedir, sizeof(homedir));
	else	/* won't need it */
		have_homedir = false;

	/* Read the client certificate file */
	if (conn->sslcert && strlen(conn->sslcert) > 0)
		strlcpy(fnbuf, conn->sslcert, sizeof(fnbuf));
	else if (have_homedir)
		snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, USER_CERT_FILE);
	else
		fnbuf[0] = '\0';

	if (fnbuf[0] == '\0')
	{
		/* no home directory, proceed without a client cert */
		have_cert = false;
	}
	else if (stat(fnbuf, &buf) != 0)
	{
		/*
		 * If file is not present, just go on without a client cert; server
		 * might or might not accept the connection.  Any other error,
		 * however, is grounds for complaint.
		 */
		if (errno != ENOENT && errno != ENOTDIR)
		{
			printfPQExpBuffer(&conn->errorMessage,
			   libpq_gettext("could not open certificate file \"%s\": %s\n"),
							  fnbuf, pqStrerror(errno, sebuf, sizeof(sebuf)));
			return errSecInternalError;
		}
		have_cert = false;
	}
	else
	{
		status = import_pem(fnbuf, buf.st_size, NULL, cert_array);
		if (status != noErr)
		{
			ssl_err_msg = SSLerrmessage(status);
			printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("could not load certificate file \"%s\": (%d) %s\n"),
								  fnbuf, status, ssl_err_msg);
			SSLerrfree(ssl_err_msg);
			return status;
		}

		have_cert = true;
	}

	if (have_cert)
	{
		if (conn->sslkey && strlen(conn->sslkey) > 0)
			strlcpy(fnbuf, conn->sslkey, sizeof(fnbuf));
		else if (have_homedir)
			snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, USER_KEY_FILE);
		else
		{
			printfPQExpBuffer(&conn->errorMessage,
							  libpq_gettext("certificate present, but private key file not found\n"));
			return errSecInternalError;
		}

		if (stat(fnbuf, &buf) != 0)
		{
			printfPQExpBuffer(&conn->errorMessage,
							  libpq_gettext("certificate present, but not private key file \"%s\"\n"),
							  fnbuf);
			return errSecInternalError;
		}

		status = import_pem(fnbuf, buf.st_size, NULL, key_array);
		if (status != noErr)
		{
			ssl_err_msg = SSLerrmessage(status);
			printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("could not load private key file \"%s\": %s\n"),
								  fnbuf, ssl_err_msg);
			SSLerrfree(ssl_err_msg);
			return status;
		}

		cert_ref = (SecCertificateRef) CFArrayGetValueAtIndex(*cert_array, 0);
		key_ref = (SecKeyRef) CFArrayGetValueAtIndex(*key_array, 0);

		identity = SecIdentityCreate(NULL /* allocator */, cert_ref, key_ref);

		cert_copy = CFArrayCreateMutableCopy(NULL /* allocator */, 0, *cert_array);
		CFArraySetValueAtIndex(cert_copy, 0, identity);

		/* FIXME: CFRelease whats not needed */

		status = SSLSetCertificate(conn->ssl, cert_copy);

		CFRelease(cert_copy);

		if (status != noErr)
		{
			ssl_err_msg = SSLerrmessage(status);
			printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("could not set certificate for connection: (%d) %s\n"),
								  status, ssl_err_msg);
			SSLerrfree(ssl_err_msg);
			return status;
		}
	}

	/* Load the root cert */
	if (conn->sslrootcert && strlen(conn->sslrootcert) > 0)
		strlcpy(fnbuf, conn->sslrootcert, sizeof(fnbuf));
	else if (have_homedir)
		snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, ROOT_CERT_FILE);
	else
		fnbuf[0] = '\0';

	if (fnbuf[0] != '\0')
	{
		if (stat(fnbuf, &buf) != 0)
		{
			/*
			 * stat() failed; assume root file doesn't exist.  If sslmode is
			 * verify-ca or verify-full, this is an error.  Otherwise, continue
			 * without performing any server cert verification.
			 */
			if (conn->sslmode[0] == 'v')	/* "verify-ca" or "verify-full" */
			{
				/*
				 * The only way to reach here with an empty filename is if
				 * pqGetHomeDirectory failed.  That's a sufficiently unusual case
				 * that it seems worth having a specialized error message for it.
				 */
				if (fnbuf[0] == '\0')
					printfPQExpBuffer(&conn->errorMessage,
									  libpq_gettext("could not get home directory to locate root certificate file\n"
													"Either provide the file or change sslmode to disable server certificate verification.\n"));
				else
					printfPQExpBuffer(&conn->errorMessage,
						libpq_gettext("root certificate file \"%s\" does not exist\n"
									  "Either provide the file or change sslmode to disable server certificate verification.\n"), fnbuf);
				return errSecInternalError;
			}
		}
		else
		{
			status = import_pem(fnbuf, buf.st_size, NULL, rootcert_array);
			if (status != noErr)
			{
				ssl_err_msg = SSLerrmessage(status);
				printfPQExpBuffer(&conn->errorMessage,
						libpq_gettext("could not load root certificate file \"%s\": %s\n"),
									  fnbuf, ssl_err_msg);
				SSLerrfree(ssl_err_msg);
				return status;
			}

			/* TODO: Load the CRL */
		}
	}

	/*
	 * Reaching here implies that the certificate and key has been loaded and
	 * verified, now we can safely set the key size used.
	 */
	conn->ssl_key_bits = SecKeyGetBlockSize(key_ref);
	return noErr;
}

/* ------------------------------------------------------------ */
/*					SSL information functions					*/
/* ------------------------------------------------------------ */

int
PQsslInUse(PGconn *conn)
{
	if (!conn)
		return 0;
	return conn->ssl_in_use;
}

/*
 *	Return pointer to the Secure Transport SSL Context object.
 */
void *
PQgetssl(PGconn *conn)
{
	if (!conn)
		return NULL;
	return conn->ssl;
}

void *
PQsslStruct(PGconn *conn, const char *struct_name)
{
	if (!conn)
		return NULL;
	if (strcmp(struct_name, "SecureTransport") == 0)
		return conn->ssl;
	return NULL;
}

const char *const *
PQsslAttributeNames(PGconn *conn)
{
	static const char *const result[] = {
		"library",
		"key_bits",
		"cipher",
		"protocol",
		NULL
	};

	return result;
}

const char *
PQsslAttribute(PGconn *conn, const char *attribute_name)
{
	SSLCipherSuite	cipher;
	SSLProtocol		protocol;
	OSStatus		status;
	const char 	   *attribute = NULL;

	if (!conn || !conn->ssl)
		return NULL;

	if (strcmp(attribute_name, "library") == 0)
		attribute = "SecureTransport";
	else if (strcmp(attribute_name, "key_bits") == 0)
	{
		if (conn->ssl_key_bits > 0)
		{
			static char sslbits_str[10];
			snprintf(sslbits_str, sizeof(sslbits_str), "%d", conn->ssl_key_bits);
			attribute = sslbits_str;
		}
	}
	else if (strcmp(attribute_name, "cipher") == 0)
	{
		status = SSLGetNegotiatedCipher(conn->ssl, &cipher);
		if (status == noErr)
			return SSLciphername(cipher);
	}
	else if (strcmp(attribute_name, "protocol") == 0)
	{
		status = SSLGetNegotiatedProtocolVersion(conn->ssl, &protocol);
		if (status == noErr)
		{
			switch (protocol)
			{
				case kTLSProtocol11:
					attribute = "TLSv1.1";
					break;
				case kTLSProtocol12:
					attribute = "TLSv1.2";
					break;
				default:
					break;
			}
		}
	}

	return attribute;
}

/* ------------------------------------------------------------ */
/*			Secure Transport Information Functions				*/
/* ------------------------------------------------------------ */

/*
 * Obtain reason string for passed SSL errcode
 */
static char ssl_noerr[] = "no SSL error reported";
static char ssl_nomem[] = "out of memory allocating error description";
#define SSL_ERR_LEN 128

static char *
SSLerrmessage(OSStatus errcode)
{
	char 	   *err_buf;
	const char *tmp;
	CFStringRef	err_msg;

	if (errcode == noErr || errcode == errSecSuccess)
		return ssl_noerr;

	err_buf = malloc(SSL_ERR_LEN);
	if (!err_buf)
		return ssl_nomem;

	err_msg = SecCopyErrorMessageString(errcode, NULL);
	if (err_msg)
	{
		tmp = CFStringGetCStringPtr(err_msg, kCFStringEncodingUTF8);
		strlcpy(err_buf, tmp, SSL_ERR_LEN);
		CFRelease(err_msg);
	}
	else
		snprintf(err_buf, sizeof(err_buf), _("SSL error code %d"), errcode);

	return err_buf;
}

static void
SSLerrfree(char *err_buf)
{
	if (err_buf && err_buf != ssl_nomem && err_buf != ssl_noerr)
		free(err_buf);
}

/*
 * SSLsessionstate
 *
 * Returns 0 if the connection is open and -1 in case the connection is closed
 * or its status unknown. If msg is non-NULL the current state is copied with
 * at most len characters.
 */
static int
SSLsessionstate(PGconn *conn, char *msg, size_t len)
{
	SSLSessionState		state = -1;
	OSStatus			status = errSecInternalError;
	const char 		   *status_msg;

	/*
	 * If conn->ssl isn't defined we will report "Unknown" which it could be
	 * argued being correct or not, but since we don't know if there has ever
	 * been a connection at all it's not more correct to say "Closed" or
	 * "Aborted".
	 */
	if (conn->ssl)
		status = SSLGetSessionState(conn->ssl, &state);

	switch (state)
	{
		case kSSLConnected:
			status_msg = "Connected";
			status = 0;
			break;
		case kSSLHandshake:
			status_msg = "Handshake";
			status = 0;
			break;
		case kSSLIdle:
			status_msg = "Idle";
			status = 0;
			break;
		case kSSLClosed:
			status_msg = "Closed";
			status = -1;
			break;
		case kSSLAborted:
			status_msg = "Aborted";
			status = -1;
			break;
		default:
			status_msg = "Unknown";
			status = -1;
			break;
	}

	if (msg)
		strlcpy(msg, status_msg, len);

	return (status == noErr ? 0 : -1);
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
