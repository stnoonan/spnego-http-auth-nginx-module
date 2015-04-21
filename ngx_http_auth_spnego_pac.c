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
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#include "ngx_http_auth_spnego_pac.h"
#include "ngx_http_auth_spnego_pac_collected.h"

#define spnego_log_error(fmt, args...) ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, fmt, ##args)
#define spnego_debug0(msg) ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg)
#define spnego_debug1(msg, one) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one)

static inline uint16_t load_16_le (const unsigned char *p)
{
    return (p[0] | (p[1] << 8));
}

static inline uint32_t load_32_le (const unsigned char *p)
{
    return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static inline uint64_t load_64_le (const unsigned char *p)
{
    return ((uint64_t)load_32_le(p+4) << 32) | load_32_le(p);
}

static inline uint64_t load_48_be (const unsigned char *p)
{
    return (uint64_t)(p[5] | (p[4] << 8) | (p[3] << 16) | (p[2] << 24) | ((uint64_t)p[1] << 32) | ((uint64_t)p[0] << 40));
}

/* parse PAC Header, alignment of the info buffers */
PACTYPE * parse_pac_header(const void *ptr, size_t len)
{
    PACTYPE *ppac_header;
    const unsigned char *p = (const unsigned char *)ptr;
    uint32_t cbuffers, version;
    size_t header_len;
    size_t i;

    if (len < PACTYPE_LENGTH)
        return NULL;

    cbuffers = load_32_le(p);
    p += 4;
    version = load_32_le(p);
    p += 4;

    if (version != 0)
        return NULL;

    header_len = PACTYPE_LENGTH + (cbuffers * PAC_INFO_BUFFER_LENGTH);
    if (len < header_len)
        return NULL;

    ppac_header = (PACTYPE *)malloc(sizeof(PACTYPE) + ((cbuffers - 1) * sizeof(PAC_INFO_BUFFER)));

    if (ppac_header == NULL)
        return NULL;

    ppac_header->cBuffers = cbuffers;
    ppac_header->Version = version;

    for (i = 0; i < ppac_header->cBuffers; i++)
    {
        PAC_INFO_BUFFER *buffer = &ppac_header->Buffers[i];

        buffer->ulType = load_32_le(p);
        p += 4;
        buffer->cbBufferSize = load_32_le(p);
        p += 4;
        buffer->Offset = load_64_le(p);
        p += 8;

        if (buffer->Offset % PAC_ALIGNMENT)
        {
            free(ppac_header);
            return NULL;
        }
        if (buffer->Offset < header_len || buffer->Offset + buffer->cbBufferSize > len)
        {
            free(ppac_header);
            return NULL;
        }
    }
    return ppac_header;
}

/* parse and output a checksum info buffer */
void parse_checksum(FILE *fp, const void *ptr, PAC_INFO_BUFFER * infoBuffer, const char *name)
{
    const unsigned char *p = (const unsigned char *)ptr;
    int32_t cksumType;
    size_t i;

    p += infoBuffer->Offset;

    if (infoBuffer->cbBufferSize < CKSUM_LENGTH)
        return;

    cksumType = load_32_le(p);
    p += 4;
    fprintf(fp, "<%s CheckSumType=\"", name);

    switch (cksumType)
    {
        case CKSUMTYPE_NONE:
            fprintf(fp, "NONE");
            break;
        case CKSUMTYPE_CRC32:
            fprintf(fp, "CRC32");
            break;
        case CKSUMTYPE_RSA_MD4:
            fprintf(fp, "RSA_MD4");
            break;
        case CKSUMTYPE_RSA_MD4_DES:
            fprintf(fp, "RSA_MD4_DES");
            break;
        case CKSUMTYPE_DES_MAC:
            fprintf(fp, "DES_MAC");
            break;
        case CKSUMTYPE_DES_MAC_K:
            fprintf(fp, "DES_MAC_K");
            break;
        case CKSUMTYPE_RSA_MD4_DES_K:
            fprintf(fp, "RSA_MD4_DES_K");
            break;
        case CKSUMTYPE_RSA_MD5:
            fprintf(fp, "RSA_MD5");
            break;
        case CKSUMTYPE_RSA_MD5_DES:
            fprintf(fp, "RSA_MD5_DES");
            break;
        case CKSUMTYPE_RSA_MD5_DES3:
            fprintf(fp, "RSA_MD5_DES3");
            break;
        case CKSUMTYPE_SHA1_OTHER:
            fprintf(fp, "SHA1_OTHER");
            break;
        case CKSUMTYPE_HMAC_SHA1_DES3:
            fprintf(fp, "HMAC_SHA1_DES3");
            break;
        case CKSUMTYPE_SHA1:
            fprintf(fp, "SHA1");
            break;
        case CKSUMTYPE_HMAC_SHA1_96_AES_128:
            fprintf(fp, "HMAC_SHA1_96_AES_128");
            break;
        case CKSUMTYPE_HMAC_SHA1_96_AES_256:
            fprintf(fp, "HMAC_SHA1_96_AES_256");
            break;
        case CKSUMTYPE_GSSAPI:
            fprintf(fp, "GSSAPI");
            break;
        case CKSUMTYPE_HMAC_MD5:
            fprintf(fp, "HMAC_MD5");
            break;
        case CKSUMTYPE_HMAC_MD5_ENC:
            fprintf(fp, "HMAC_MD5_ENC");
            break;
    }
    fprintf(fp, "\">");
    for (i = 4; i < infoBuffer->cbBufferSize; i++)
    {
        fprintf(fp, "%02X", *p++);
    }

    fprintf(fp, "</%s>\n", name);
}

/* parse and output the UPN DNS info buffer */
void parse_upn_dns_info(FILE *fp, const void *ptr, PAC_INFO_BUFFER * infoBuffer)
{
    const unsigned char *p = (const unsigned char *)ptr;
    const unsigned char *p1;
    const unsigned char *p2;
    uint16_t len;
    uint16_t pos;
    size_t i;

    p += infoBuffer->Offset;
    p1 = p;

    fprintf(fp, "<UPN_DNS_Info>\n");
    do {
        len = load_16_le(p);
        p += 2;
        pos = load_16_le(p);
        p += 2;
        if (len == 0)
        {
            fprintf(fp, "</UPN_DNS_Info>\n");
            return;
        }
        p2 = p1 + pos;

        for (i = 0; i < len; i+=2)
        {
            fprintf(fp, "%c", *p2++);
            p2++;
        }
        fprintf(fp, "\n");
    } while(1);
}

/* convert kerberos timestamp to seconds since 1970 */
int32_t k5_time_to_seconds_since_1970(int64_t ntTime)
{
    uint64_t abstime;

    ntTime /= 10000000;

    abstime = ntTime > 0 ? ntTime - NT_TIME_EPOCH : -ntTime;

    if (abstime > KRB5_INT32_MAX)
        return 0;

    return abstime;
}

/* parse and output the client info buffer */
void parse_client_info(FILE *fp, const void *ptr, PAC_INFO_BUFFER * infoBuffer)
{
    const unsigned char *p = (const unsigned char *)ptr;
    int64_t nt_authtime;
    uint16_t princname_length;
    size_t i;

    p += infoBuffer->Offset;

    if (infoBuffer->cbBufferSize < CLIENT_INFO_LENGTH)
        return;

    nt_authtime = load_64_le(p);
    p += 8;
    princname_length = load_16_le(p);
    p += 2;
    nt_authtime = k5_time_to_seconds_since_1970(nt_authtime);

    fprintf(fp, "<ClientInfo NTAuthTime=\"%lu\">", nt_authtime);

    for (i = 0; i < princname_length; i+=2)
    {
        fprintf(fp, "%c", *p++);
        p++;
    }

    fprintf(fp, "</ClientInfo>\n");
}

/* parse and output a kerberos timestamp */
void parse_k5_time(FILE *fp, const char * format, const unsigned char **p)
{
    int64_t nt_time = load_64_le(*p);
    *p += 8;
    fprintf(fp, format, k5_time_to_seconds_since_1970(nt_time));
}

/* parse and output a uint16 value */
void parse_uint16(FILE *fp, const char * format, const unsigned char **p)
{
    uint16_t res = load_16_le(*p);
    *p += 2;
    fprintf(fp, format, res);
}

/* parse and output a uint32 value */
void parse_uint32(FILE *fp, const char * format, const unsigned char **p)
{
    uint32_t res = load_32_le(*p);
    *p += 4;
    fprintf(fp, format, res);
}

/* parse and the user flags */
void parse_user_flgs(FILE *fp, const uint32_t user_flgs)
{
    uint8_t listFlag = 0;
    if (user_flgs & NETLOGON_GUEST)
    {
        fprintf(fp, "GUEST");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_NOENCRYPTION)
    {
        fprintf(fp, "%sNOENCRYPTION", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_CACHED_ACCOUNT)
    {
        fprintf(fp, "%sCACHED_ACCOUNT", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_USED_LM_PASSWORD)
    {
        fprintf(fp, "%sUSED_LM_PASSWORD", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_EXTRA_SIDS)
    {
        fprintf(fp, "%sEXTRA_SIDS", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_SUBAUTH_SESSION_KEY)
    {
        fprintf(fp, "%sSUBAUTH_SESSION_KEY", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_SERVER_TRUST_ACCOUNT)
    {
        fprintf(fp, "%sSERVER_TRUST_ACCOUNT", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_NTLMV2_ENABLED)
    {
        fprintf(fp, "%sNTLMV2_ENABLED", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_RESOURCE_GROUPS)
    {
        fprintf(fp, "%sRESOURCE_GROUPS", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_PROFILE_PATH_RETURNED)
    {
        fprintf(fp, "%sPROFILE_PATH_RETURNED", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (user_flgs & NETLOGON_GRACE_LOGON)
    {
        fprintf(fp, "%sGRACE_LOGON", listFlag == 1 ? "," : "");
    }
}

/* parse and output a UNISTR2 value */
void parse_UNISTR2(FILE *fp, const unsigned char **p)
{
    uint32_t uni_max_len;
    uint32_t offset;
    uint32_t uni_str_len;
    size_t i;

    uni_max_len = load_32_le(*p); *p += 4;
    offset = load_32_le(*p); *p += 4;
    uni_str_len = load_32_le(*p); *p += 4;

    for (i = 0; i < uni_str_len; i++)
    {
        fprintf(fp, "%c", **p);
        *p += 2;
    }
    if (i % 2 == 1)
    {
        *p += 2;
    }
}

/* parse and output a DOM_SID2 value */
void parse_DOM_SID2(FILE *fp, const unsigned char **p)
{
    uint32_t num_auths;
    uint8_t  sid_no;
    uint8_t  num_auths2;
    uint64_t id_auth;
    uint32_t auth;
    size_t i;

    num_auths = load_32_le(*p); *p += 4;
    sid_no = (uint8_t)(**p); *p += 1;
    num_auths2 = (uint8_t)**p; *p += 1;
    id_auth = load_48_be(*p); *p += 6;

    fprintf(fp, "S-%u-%lu", sid_no, id_auth);

    for (i = 0; i < num_auths2; i++)
    {
        auth = load_32_le(*p); *p += 4;
        fprintf(fp, "-%u", auth);
    }
}

/* parse and output SID or RID attributes */
void parse_dom_attribute(FILE *fp, uint32_t attr)
{
    uint8_t listFlag = 0;
    if (attr & SE_GROUP_MANDATORY)
    {
        fprintf(fp, "MANDATORY");
        listFlag = 1;
    }
    if (attr & SE_GROUP_ENABLED_BY_DEFAULT)
    {
        fprintf(fp, "%sENABLED_BY_DEFAULT", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_ENABLED)
    {
        fprintf(fp, "%sENABLED", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_OWNER)
    {
        fprintf(fp, "%sOWNER", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_USE_FOR_DENY_ONLY)
    {
        fprintf(fp, "%sUSE_FOR_DENY_ONLY", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_INTEGRITY)
    {
        fprintf(fp, "%sINTEGRITY", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_INTEGRITY_ENABLED)
    {
        fprintf(fp, "%sINTEGRITY_ENABLED", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    if (attr & SE_GROUP_RESOURCE)
    {
        fprintf(fp, "%sRESOURCE", listFlag == 1 ? "," : "");
        listFlag = 1;
    }
    fprintf(fp, "%s%u", listFlag == 1 ? "," : "", ((attr & SE_GROUP_LOGON_ID) >> 30));
}

/* parse and output a RID with attributes */
void parse_rid_with_attribute(FILE *fp, DOM_GID * rid)
{
    fprintf(fp,"<GroupRID attributes=\"");
    parse_dom_attribute(fp, rid->attr);
    fprintf(fp,"\">%u</GroupRID>\n", rid->g_rid);
}

/* parse and output a SID with attributes */
void parse_sid_with_attribute(FILE *fp, const unsigned char **p, DOM_GID * rid)
{
    fprintf(fp,"<GroupSID attributes=\"");
    parse_dom_attribute(fp, rid->attr);
    fprintf(fp,"\">");
    parse_DOM_SID2(fp, p);
    fprintf(fp,"</GroupSID>\n", rid->g_rid);
}

/* parse and output the NET_USER_INFO_3 info buffer */
void parse_logon_info(ngx_http_request_t *r, FILE *fp, const void *ptr, PAC_INFO_BUFFER * infoBuffer)
{
    const unsigned char *p = (const unsigned char *)ptr;
    int64_t nt_time;
    UNIHDR* hdr_user_name;
    UNIHDR* hdr_full_name;
    UNIHDR* hdr_logon_script;
    UNIHDR* hdr_profile_path;
    UNIHDR* hdr_home_dir;
    UNIHDR* hdr_dir_drive;
    UNIHDR* hdr_logon_srv;
    UNIHDR* hdr_logon_dom;
    uint32_t ptr_user_info;
    uint32_t num_groups;
    uint32_t buffer_groups;
    uint32_t user_flgs;
    uint8_t listFlag = 0;
    uint32_t buffer_dom_id;
    uint32_t num_other_sids;
    uint32_t buffer_other_sids;
    uint32_t num_groups2;
    uint32_t num_sids;
    DOM_GID *gids;
    size_t i;

    p += infoBuffer->Offset;

    /* Common Type Header for the Serialization Stream 
     * http://msdn.microsoft.com/en-us/library/cc243890.aspx
     */
    
    if (*p != 0x01)   /* Version */
    {
        spnego_log_error("NET_USER_INFO_3 version mismatch: 0x%02x", *p);
        return;
    }
    p++;
    
    if (*p != 0x10)   /* Endianness */
    {
        spnego_log_error("NET_USER_INFO_3 endianness mismatch: 0x%02x", *p);
        return;
    }
    p++;
    
    if (load_16_le(p) != 0x0008)   /* CommonHeaderLength  */
    {
        spnego_log_error("NET_USER_INFO_3 common header length mismatch: 0x%04x", load_16_le(p));
        return;
    }
    p += 2;
    
    if (load_32_le(p) != 0xCCCCCCCC)   /* Filler */
    {
        spnego_log_error("NET_USER_INFO_3 filler mismatch: 0x%04x", load_32_le(p));
        return;
    }
    p += 4;
    
    
    p += 4; /* length of the info buffer */
    p += 4; /* is zero */

    fprintf(fp,"<LogonInfo>\n");

    ptr_user_info = load_32_le(p); p += 4;

    fprintf(fp,"<UserInfo3 ");

    parse_k5_time(fp, "LogonTime=\"%lu\" ", &p);
    parse_k5_time(fp, "LogoffTime=\"%lu\" ", &p);
    parse_k5_time(fp, "KickoffTime=\"%lu\" ", &p);
    parse_k5_time(fp, "PasswordLastSetTime=\"%lu\" ", &p);
    parse_k5_time(fp, "PasswordCanChangeTime=\"%lu\" ", &p);
    parse_k5_time(fp, "PasswordMustChangeTime=\"%lu\" ", &p);

    hdr_user_name = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_full_name = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_logon_script = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_profile_path = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_home_dir = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_dir_drive = (UNIHDR *)p; p += sizeof(UNIHDR);

    parse_uint16(fp, "LogonCount=\"%u\" ", &p);
    parse_uint16(fp, "BadPasswordCount=\"%u\" ", &p);
    parse_uint32(fp, "UserRID=\"%u\" ", &p);
    parse_uint32(fp, "GroupRID=\"%u\" ", &p);

    num_groups = load_32_le(p); p += 4;
    buffer_groups = load_32_le(p); p += 4;
    user_flgs = load_32_le(p); p += 4;

    fprintf(fp,"UserFlags=\"");
    parse_user_flgs(fp, user_flgs);
    fprintf(fp,"\" ");

    fprintf(fp,"UserSessionKey=\"");
    for (i = 0; i < 16; i++)
    {
        fprintf(fp,"%02X", *p++);
    }
    fprintf(fp,"\" ");

    hdr_logon_srv = (UNIHDR *)p; p += sizeof(UNIHDR);
    hdr_logon_dom = (UNIHDR *)p; p += sizeof(UNIHDR);

    buffer_dom_id = load_32_le(p); p += 4;

    /* Padding is type of LMSessKey
     * currently I don't know for what this is.
     * If you need it, implement it!
LMSessKey: struct netr_LMSessionKey
    key                      : 0000000000000000
acct_flags               : 0x00000014 (20)
       0: ACB_DISABLED             
       0: ACB_HOMDIRREQ            
       1: ACB_PWNOTREQ             
       0: ACB_TEMPDUP              
       1: ACB_NORMAL               
       0: ACB_MNS                  
       0: ACB_DOMTRUST             
       0: ACB_WSTRUST              
       0: ACB_SVRTRUST             
       0: ACB_PWNOEXP              
       0: ACB_AUTOLOCK             
       0: ACB_ENC_TXT_PWD_ALLOWED  
       0: ACB_SMARTCARD_REQUIRED   
       0: ACB_TRUSTED_FOR_DELEGATION
       0: ACB_NOT_DELEGATED        
       0: ACB_USE_DES_KEY_ONLY     
       0: ACB_DONT_REQUIRE_PREAUTH 
       0: ACB_PW_EXPIRED           
       0: ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
       0: ACB_NO_AUTH_DATA_REQD    
       0: ACB_PARTIAL_SECRETS_ACCOUNT
       0: ACB_USE_AES_KEYS         
unknown: ARRAY(7)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
    unknown                  : 0x00000000 (0)
     */
    fprintf(fp,"Padding=\"");
    for (i = 0; i < 40; i++)
    {
        fprintf(fp,"%02X", *p++);
    }
    fprintf(fp,"\" ");
    
    num_other_sids = load_32_le(p); p += 4;
    buffer_other_sids = load_32_le(p); p += 4;

    /* Step Over next UNISTR2 element.
     * This element is referenced by the ptr_user_info, it should be empty.
     */
    parse_UNISTR2(fp, &p);

    fprintf(fp,"UserName=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" UserFullName=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" LogonScript=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" ProfilePath=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" HomeDir=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" DirDrive=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" ");

    num_groups2 = load_32_le(p); p += 4;
    gids = (DOM_GID *)p;
    p += sizeof(DOM_GID) * num_groups2;

    fprintf(fp,"LogonServer=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" LogonDomain=\"");
    parse_UNISTR2(fp, &p);
    fprintf(fp,"\" DomainSID=\"");
    parse_DOM_SID2(fp, &p);
    fprintf(fp,"\">\n");

    for (i = 0; i < num_groups2; i++)
    {
        parse_rid_with_attribute(fp, &gids[i]);
    }
    num_sids = load_32_le(p); p += 4;
    
    gids = (DOM_GID *)p;
    p += sizeof(DOM_GID) * num_sids;
    
    for (i = 0; i < num_sids; i++)
    {
        parse_sid_with_attribute(fp, &p, &gids[i]);
    }

    fprintf(fp, "</UserInfo3>\n");
    
    /* Not implemented Resource Group, because I don't have that.
     * PSID ResourceGroupDomainSid;
     * ULONG ResourceGroupCount;
     * [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
     */
    
    fprintf(fp, "</LogonInfo>\n");
}

/* check the file modified time and the existance of the output xml */
int check_file(const char* filename, ngx_int_t cache_time)
{
    struct stat buffer;
    int exist = stat(filename, &buffer);
    time_t now;
    time(&now);
    if(exist == 0)
    {
        if (buffer.st_mtime + cache_time < time(NULL))
        {
            return 0;
        }
        return 1;
    }
    else // -1
        return 0;
}

void ngx_http_auth_spnego_pac_to_file(ngx_http_request_t *r, gss_buffer_desc * pac_buffer, const char *filename, ngx_int_t cache_time)
{
    PACTYPE *ppac_header;
    FILE *outFile;
    size_t i;
    
    if(check_file(filename, cache_time))
    {
        return;
    }

    outFile = fopen(filename, "w");
    if (!outFile)
    {
        spnego_log_error("Unable to open file %s", filename);
        return;
    }
    fprintf(outFile, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
    fprintf(outFile, "<PAC>\n");

    ppac_header = parse_pac_header(pac_buffer->value, pac_buffer->length);
    if (ppac_header != NULL)
    {
        for (i = 0; i < ppac_header->cBuffers; i++)
        {
            switch (ppac_header->Buffers[i].ulType)
            {
                case KRB5_PAC_LOGON_INFO:
                    parse_logon_info(r, outFile, pac_buffer->value,  &ppac_header->Buffers[i]);
                    break;
                case KRB5_PAC_CREDENTIALS_INFO:
                    spnego_debug0("KRB5_PAC_CREDENTIALS_INFO");
                    break;
                case KRB5_PAC_SERVER_CHECKSUM:
                    parse_checksum(outFile, pac_buffer->value,  &ppac_header->Buffers[i], "ServerCheckSum");
                    break;
                case KRB5_PAC_PRIVSVR_CHECKSUM:
                    parse_checksum(outFile, pac_buffer->value, &ppac_header->Buffers[i], "PrivateServerCheckSum");
                    break;
                case KRB5_PAC_CLIENT_INFO:
                    parse_client_info(outFile, pac_buffer->value, &ppac_header->Buffers[i]);
                    break;
                case KRB5_PAC_DELEGATION_INFO:
                    spnego_debug0("KRB5_PAC_DELEGATION_INFO");
                    break;
                case KRB5_PAC_UPN_DNS_INFO:
                    parse_upn_dns_info(outFile, pac_buffer->value, &ppac_header->Buffers[i]);
                    break;
                default:
                    spnego_debug1("KRB5_PAC_BUFFER_TYPE: %d", ppac_header->Buffers[i].ulType);
                    break;
            }
        }
        free(ppac_header);
    }
    fprintf(outFile, "</PAC>\n");
    fclose(outFile);
}

