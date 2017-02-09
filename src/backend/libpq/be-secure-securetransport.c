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
extern void *st_allocate(CFIndex size, CFOptionFlags hint, void *info);
extern void *st_reallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info);
extern void st_deallocate(void *ptr, void *info);
extern CFIndex st_preferredSize(CFIndex size, CFOptionFlags hint, void *info);

static void SSLLoadCertificate(Port *port);
static OSStatus load_key(Port *port, char *filename, CFArrayRef *key);
static OSStatus load_certificate(Port *port, char *filename, CFArrayRef *certificate);
static OSStatus load_certificate_keychain(Port *port, char *cert_name, CFArrayRef *certificate);
static OSStatus load_pkcs12_file(Port *port, char *p12_fname, CFArrayRef *items);
static OSStatus load_pem_file(Port *port, char *pem_fname, int size, CFArrayRef *items);
static char * SSLerrmessage(OSStatus status);
static OSStatus SSLSocketWrite(SSLConnectionRef conn, const void *data, size_t *len);
static OSStatus SSLSocketRead(SSLConnectionRef conn, void *data, size_t *len);
static char * SSLerrmessage(OSStatus status);
static const char * SSLciphername(SSLCipherSuite cipher);

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
	SecTrustRef			trust;
	SecTrustResultType	trust_eval = 0;

	Assert(!port->ssl);

	port->ssl = (void *) SSLCreateContext(NULL, kSSLServerSide, kSSLStreamType);
	if (!port->ssl)
	{
		ereport(FATAL,
				(errmsg("could not create SSL context")));
	}

	port->ssl_in_use = true;
	port->ssl_buffered = 0;

//	if (ssl_ca_file[0])
//		SSLSetClientSideAuthenticate((SSLContextRef) port->ssl, kAlwaysAuthenticate);

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

	SSLLoadCertificate(port);

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

		if (status == errSSLPeerAuthCompleted)
		{
			status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
			if (status != noErr || trust == NULL)
			{
				ereport(WARNING,
					(errmsg("SSLCopyPeerTrust returned: \"%s\"",
					 SSLerrmessage(status))));
				return -1;
			}

			if (ssl_loaded_verify_locations && port->rootcert != NULL)
			{
				status = SecTrustSetAnchorCertificates(trust, (CFArrayRef) port->rootcert);
				if (status != noErr)
				{
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificates returned: \"%s\"",
						 SSLerrmessage(status))));
					return -1;
				}

				status = SecTrustSetAnchorCertificatesOnly(trust, false);
				if (status != noErr)
				{
					ereport(WARNING,
						(errmsg("SecTrustSetAnchorCertificatesOnly returned: \"%s\"",
						 SSLerrmessage(status))));
					return -1;
				}
			}

			status = SecTrustEvaluate(trust, &trust_eval);
			if (status != noErr)
			{
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
					//port->peer_cert_valid = true;
					//break;
				/*
				 * Treat all other cases as rejection without further questioning.
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
		}
	}

#if 0
		//ereport(NOTICE, (errmsg("be_tls_open_server initiating handshake for CA")));

		do
		{
			status = SSLHandshake((SSLContextRef) port->ssl);
		}
		while (status == errSSLWouldBlock || status == -1);

		if (status != noErr)
		{
			ereport(WARNING,
					(errmsg("SSLHandshake returned: \"%s\"",
					 SSLerrmessage(status))));
			return -1;
		}

		if (status == noErr)
			return 0;

		return -1;

		status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
		if (status != noErr || trust == NULL)
		{
			ereport(WARNING,
					(errmsg("SSLCopyPeerTrust returned: \"%s\"",
					 SSLerrmessage(status))));
			return -1;
		}

		status = SecTrustSetAnchorCertificates(trust, (CFArrayRef) port->rootcert);
		if (status != noErr)
			return -1;

		status = SecTrustSetAnchorCertificatesOnly(trust, false);
		if (status != noErr)
			return -1;

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
				/*
				 * Treat all other cases as rejection without further questioning.
				 */
				default:
					port->peer_cert_valid = false;
					break;
			}
		}

		SecCertificateRef usercert = SecTrustGetCertificateAtIndex(trust, 0L);

		CFStringRef usercert_cn;
		SecCertificateCopyCommonName(usercert, &usercert_cn);
		port->peer_cn = pstrdup(CFStringGetCStringPtr(usercert_cn, kCFStringEncodingUTF8));

		CFRelease(usercert_cn);

		CFRelease(trust);
	}
	else
		status = SSLHandshake((SSLContextRef) port->ssl);

#endif

	if (status != noErr)
		return -1;

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
	CFArrayRef			rootcert;
	SecIdentityRef		identity;
	SecCertificateRef	cert_ref;
	SecKeyRef			key_ref;
	SecPolicyRef		policy;
	SecTrustRef			trust;
	SecTrustResultType	trust_status;
	CSSM_TP_APPLE_EVIDENCE_INFO *status_chain;
	CFArrayRef			chain;
	CFMutableArrayRef	chain_copy;

	status = load_certificate(port, ssl_cert_file, &certificate);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not load server certificate: \"%s\"",
				 SSLerrmessage(status))));
	}

	status = load_key(port, ssl_key_file, &key);
	if (status != noErr)
	{
		ereport(FATAL,
				(errmsg("could not load private key: \"%s\"",
				 SSLerrmessage(status))));
	}

	cert_ref = (SecCertificateRef) CFArrayGetValueAtIndex(certificate, 0);
	key_ref = (SecKeyRef) CFArrayGetValueAtIndex(key, 0);
	policy = SecPolicyCreateSSL(true, NULL);
	identity = SecIdentityCreate(NULL, cert_ref, key_ref);

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
		status = load_certificate(port, ssl_ca_file, &rootcert);
		if (status != noErr)
		{
			ereport(FATAL,
					(errmsg("could not load root certificate: \"%s\"",
					 SSLerrmessage(status))));
		}
		
		status = SecTrustSetAnchorCertificates(trust, rootcert);
		if (status != noErr)
		{
			ereport(FATAL,
					(errmsg("unable to add root certificate to chain: \"%s\"",
					 SSLerrmessage(status))));
		}
		SecTrustSetAnchorCertificatesOnly(trust, false);
		ssl_loaded_verify_locations = true;
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

	chain_copy = CFArrayCreateMutable(NULL, CFArrayGetCount(chain), &kCFTypeArrayCallBacks);
	
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

	if (rootcert)
		port->rootcert = (void *) CFRetain(rootcert);
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
	OSStatus 	write_status;

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

int
be_tls_get_cipher_bits(Port *port)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	SecKeyRef			key;

	status = SSLCopyPeerTrust((SSLContextRef) port->ssl, &trust);
	if (status == noErr)
	{
		cert = SecTrustGetCertificateAtIndex(trust, 0);
		status = SecCertificateCopyPublicKey(cert, &key);
		if (status == noErr)
			return SecKeyGetBlockSize(key);
	}

	return 0;
}

void
be_tls_get_peerdn_name(Port *port, char *ptr, size_t len)
{
	OSStatus			status;
	SecTrustRef			trust;
	SecCertificateRef	cert;
	CFDataRef			dn;
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

void
be_tls_get_cipher(Port *port, char *ptr, size_t len)
{
	OSStatus		status;
	SSLCipherSuite	cipher;

	status = SSLGetNegotiatedCipher((SSLContextRef) port->ssl, &cipher);
	if (status == noErr)
		strlcpy(ptr, SSLciphername(cipher), len);
	else
		ptr[0] = '\0';
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
/*			Internal functions - Certificate Management			*/
/* ------------------------------------------------------------ */

static OSStatus
load_key(Port *port, char *filename, CFArrayRef *key)
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
			status = load_pem_file(port, filename, stat_buf.st_size, key);
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
load_certificate(Port *port, char *filename, CFArrayRef *certificate)
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
load_certificate_keychain(Port *port, char *cert_name, CFArrayRef *certificate)
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
load_pkcs12_file(Port *port, char *p12_fname, CFArrayRef *items)
{
	OSStatus		status;
	CFURLRef		p12_ref;
	CFDataRef		buf;

	const void	   *keys[] = {};
	const void	   *vals[] = {};

	CFDictionaryRef opt = CFDictionaryCreate(NULL, keys, vals, 0, NULL, NULL);

	p12_ref = CFURLCreateFromFileSystemRepresentation(NULL,
					(UInt8 *) p12_fname, strlen(p12_fname), false);

	if (CFURLCreateDataAndPropertiesFromResource(NULL, p12_ref, &buf, NULL, NULL, &status))
	{
		status = SecPKCS12Import(buf, opt, items);
		CFRelease(buf);
	}

	CFRelease(opt);
	CFRelease(p12_ref);

	return status;
}

static OSStatus
load_pem_file(Port *port, char *pem_fname, int size, CFArrayRef *items)
{
	OSStatus							status;
	FILE							   *cert_fd;
	UInt8							   *cert_buf;
	int									ret;
	CFDataRef							data_ref;
	SecItemImportExportKeyParameters	params;
	CFStringRef							cert_path;
	SecExternalFormat					format;
	SecExternalItemType					item_type;

	cert_buf = palloc(size);

	cert_fd = fopen(pem_fname, "r");
	if (cert_fd < 0)
		ereport(FATAL,
				(errcode_for_file_access(),
				 errmsg("could not load server certificate file \"%s\": %m",
				 pem_fname)));

	ret = fread(cert_buf, 1, size, cert_fd);

	/*
	 * TODO: Handle reading the certificate in chunks
	 */
	if (ret != size)
	{
		fclose(cert_fd);
		return errSecInternalError;
	}

	fclose(cert_fd);

	data_ref = CFDataCreate(NULL, cert_buf, size);

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
	cert_path = CFStringCreateWithCString(NULL, pem_fname,
										  kCFStringEncodingUTF8);

	item_type = kSecItemTypeCertificate;

	/*
	 * We are currently not importing the certificate into a keychain but
	 * a future TODO is to create a transient keychain which exists for
	 * the duration of the server process for holding the certificates.
	 */
	status = SecItemImport(data_ref, cert_path, &format, &item_type,
						   0 /* flags */, &params, NULL /* keychain */,
						   items);

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
