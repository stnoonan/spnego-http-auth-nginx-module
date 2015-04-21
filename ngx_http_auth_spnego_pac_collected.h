/*
 * Copyright (C) 2014 Sven Fabricius <sven.fabricius{at}livediesel[dot]de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Collected constants and structs of various kerberos, gssapi and samba header files
 * http://msdn.microsoft.com/en-us/library/aa302203.aspx
 */

#ifndef NGX_HTTP_AUTH_SPNEGO_PAC_COLLECTED_H_
#define NGX_HTTP_AUTH_SPNEGO_PAC_COLLECTED_H_

#define PAC_INFO_BUFFER_LENGTH           16
#define PACTYPE_LENGTH                   8U
#define CKSUM_LENGTH                     4
#define CLIENT_INFO_LENGTH               10
#define PAC_ALIGNMENT                    8
#define NT_TIME_EPOCH                    11644473600LL
#define KRB5_INT32_MAX                   2147483647

#define KRB5_PAC_LOGON_INFO              1  /**< Logon information */
#define KRB5_PAC_CREDENTIALS_INFO        2  /**< Credentials information */
#define KRB5_PAC_SERVER_CHECKSUM         6  /**< Server checksum */
#define KRB5_PAC_PRIVSVR_CHECKSUM        7  /**< KDC checksum */
#define KRB5_PAC_CLIENT_INFO             10 /**< Client name and ticket info */
#define KRB5_PAC_DELEGATION_INFO         11 /**< Constrained delegation info */
#define KRB5_PAC_UPN_DNS_INFO            12 /**< User principal name and DNS info */

#define NETLOGON_GUEST                   0x00000001
#define NETLOGON_NOENCRYPTION            0x00000002
#define NETLOGON_CACHED_ACCOUNT          0x00000004
#define NETLOGON_USED_LM_PASSWORD        0x00000008
#define NETLOGON_EXTRA_SIDS              0x00000020
#define NETLOGON_SUBAUTH_SESSION_KEY     0x00000040
#define NETLOGON_SERVER_TRUST_ACCOUNT    0x00000080
#define NETLOGON_NTLMV2_ENABLED          0x00000100
#define NETLOGON_RESOURCE_GROUPS         0x00000200
#define NETLOGON_PROFILE_PATH_RETURNED   0x00000400
#define NETLOGON_GRACE_LOGON             0x01000000

#define SE_GROUP_MANDATORY               0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT      0x00000002
#define SE_GROUP_ENABLED                 0x00000004
#define SE_GROUP_OWNER                   0x00000008
#define SE_GROUP_USE_FOR_DENY_ONLY       0x00000010
#define SE_GROUP_INTEGRITY               0x00000020
#define SE_GROUP_INTEGRITY_ENABLED       0x00000040
#define SE_GROUP_RESOURCE                0x20000000
#define SE_GROUP_LOGON_ID                0xC0000000

#ifdef CKSUMTYPE_CRC32
#undef CKSUMTYPE_CRC32
#endif
#ifdef CKSUMTYPE_RSA_MD4
#undef CKSUMTYPE_RSA_MD4
#endif
#ifdef CKSUMTYPE_RSA_MD4_DES
#undef CKSUMTYPE_RSA_MD4_DES
#endif
#ifdef CKSUMTYPE_RSA_MD5
#undef CKSUMTYPE_RSA_MD5
#endif
#ifdef CKSUMTYPE_RSA_MD5_DES
#undef CKSUMTYPE_RSA_MD5_DES
#endif
#ifdef CKSUMTYPE_HMAC_SHA1_DES3
#undef CKSUMTYPE_HMAC_SHA1_DES3
#endif

#define CKSUMTYPE_NONE                   0
#define CKSUMTYPE_CRC32                  1
#define CKSUMTYPE_RSA_MD4                2
#define CKSUMTYPE_RSA_MD4_DES            3
#define CKSUMTYPE_DES_MAC                4
#define CKSUMTYPE_DES_MAC_K              5
#define CKSUMTYPE_RSA_MD4_DES_K          6
#define CKSUMTYPE_RSA_MD5                7
#define CKSUMTYPE_RSA_MD5_DES            8
#define CKSUMTYPE_RSA_MD5_DES3           9
#define CKSUMTYPE_SHA1_OTHER             10
#define CKSUMTYPE_HMAC_SHA1_DES3         12
#define CKSUMTYPE_SHA1                   14
#define CKSUMTYPE_HMAC_SHA1_96_AES_128   15
#define CKSUMTYPE_HMAC_SHA1_96_AES_256   16
#define CKSUMTYPE_GSSAPI                 32771
#define CKSUMTYPE_HMAC_MD5               -138
#define CKSUMTYPE_HMAC_MD5_ENC           -1138

typedef struct _PAC_INFO_BUFFER {
    uint32_t ulType;
    uint32_t cbBufferSize;
    uint64_t Offset;
} PAC_INFO_BUFFER;

typedef struct _PACTYPE {
    uint32_t cBuffers;
    uint32_t Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE;

typedef struct {
    uint32_t g_rid;
    uint32_t attr;
} DOM_GID;

typedef struct {
    uint16_t uni_str_len;
    uint16_t uni_max_len;
    uint32_t buffer;
} UNIHDR;

#endif /* NGX_HTTP_AUTH_SPNEGO_PAC_COLLECTED_H_ */
