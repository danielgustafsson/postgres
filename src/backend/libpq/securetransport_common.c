/*-------------------------------------------------------------------------
 *
 * securetransport_common.c
 *	  Set of common functions for macOS Secure Transport support shared
 *	  between frontend and backend
 *
 * This should only be used (compiled) if code is compiled with Secure
 * Transport support.
 *
 *
 * Copyright (c) 2017, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *        src/backend/libpq/securetransport_common.c
 *
 *-------------------------------------------------------------------------
 */

#include <Security/SecureTransport.h>

const char * SSLciphername(SSLCipherSuite cipher);

/*
 * SSLciphername
 *
 * Translate a SSLCipherSuite code into a string literal suitable for printing
 * in log/informational messages to the user. Since this implementation of the
 * Secure Transport lib doesn't support SSLv2/v3 these ciphernames are omitted.
 *
 * This only removes the TLS_ portion of the SSLCipherSuite enum label for the
 * ciphers to match what most Secure Transport implementations seem to be doing
 */
const char *
SSLciphername(SSLCipherSuite cipher)
{
	switch (cipher)
	{
		case TLS_NULL_WITH_NULL_NULL:
			return "NULL";
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
