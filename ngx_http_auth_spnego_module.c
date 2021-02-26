/*
 * Copyright (C) 2009 Michal Kowalski <superflouos{at}gmail[dot]com>
 * Copyright (C) 2012-2013 Sean Timothy Noonan <stnoonan@obsolescence.net>
 * Copyright (C) 2013 Marcello Barnaba <vjt@openssl.it>
 * Copyright (C) 2013 Alexander Pyhalov <alp@sfedu.ru>
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

#include <stdbool.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

#define spnego_log_krb5_error(context,code) {\
    const char* ___kerror = krb5_get_error_message(context, code);\
    spnego_debug2("Kerberos error: %d, %s", code , ___kerror);\
    krb5_free_error_message( context, ___kerror  ); }
#define spnego_error(code) ret = code; goto end
#define spnego_debug0(msg) ngx_log_debug0(\
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg)
#define spnego_debug1(msg, one) ngx_log_debug1(\
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one)
#define spnego_debug2(msg, one, two) ngx_log_debug2(\
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one, two)
#define spnego_debug3(msg, one, two, three) ngx_log_debug3(\
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one, two, three)
#define spnego_log_error(fmt, args...) ngx_log_error(\
        NGX_LOG_ERR, r->connection->log, 0, fmt, ##args)

/* Module handler */
static ngx_int_t ngx_http_auth_spnego_handler(ngx_http_request_t *);

static void *ngx_http_auth_spnego_create_loc_conf(ngx_conf_t *);
static char *ngx_http_auth_spnego_merge_loc_conf(
        ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_spnego_init(ngx_conf_t *);

ngx_int_t
ngx_http_auth_spnego_set_bogus_authorization(ngx_http_request_t * r);

    const char *
get_gss_error(
        ngx_pool_t * p,
        OM_uint32 error_status,
        char *prefix)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf[1024];
    size_t len;
    ngx_str_t str;
    ngx_snprintf((u_char *) buf, sizeof(buf), "%s: %Z", prefix);
    len = ngx_strlen(buf);
    do {
        maj_stat =
            gss_display_status(&min_stat, error_status, GSS_C_MECH_CODE,
                    GSS_C_NO_OID, &msg_ctx, &status_string);
        if (sizeof(buf) > len + status_string.length + 1) {
            ngx_sprintf((u_char *) buf + len, "%s:%Z",
                    (char *) status_string.value);
            len += (status_string.length + 1);
        }
        gss_release_buffer(&min_stat, &status_string);
    }
    while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

    str.len = len + 1; /* "include" '\0' */
    str.data = (u_char *) buf;
    return (char *) (ngx_pstrdup(p, &str));
}

/* per request/connection */
typedef struct {
    ngx_str_t token; /* decoded Negotiate token */
    ngx_int_t head; /* non-zero flag if headers set */
    ngx_int_t ret; /* current return code */
    ngx_str_t token_out_b64; /* base64 encoded output tokent */
} ngx_http_auth_spnego_ctx_t;

typedef struct {
    ngx_flag_t protect;
    ngx_str_t realm;
    ngx_str_t keytab;
    ngx_str_t srvcname;
    ngx_flag_t fqun;
    ngx_flag_t force_realm;
    ngx_flag_t allow_basic;
    ngx_array_t *auth_princs;
    ngx_flag_t map_to_local;
} ngx_http_auth_spnego_loc_conf_t;

#define SPNEGO_NGX_CONF_FLAGS NGX_HTTP_MAIN_CONF\
    | NGX_HTTP_SRV_CONF\
| NGX_HTTP_LOC_CONF\
| NGX_HTTP_LMT_CONF\
| NGX_CONF_FLAG

/* Module Directives */
static ngx_command_t ngx_http_auth_spnego_commands[] = {
    {ngx_string("auth_gss"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, protect),
        NULL},

    {ngx_string("auth_gss_realm"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, realm),
        NULL},

    {ngx_string("auth_gss_keytab"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, keytab),
        NULL},

    {ngx_string("auth_gss_service_name"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, srvcname),
        NULL},

    {ngx_string("auth_gss_format_full"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, fqun),
        NULL},

    {ngx_string("auth_gss_force_realm"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, force_realm),
        NULL},

    {ngx_string("auth_gss_allow_basic_fallback"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, allow_basic),
        NULL},

    {ngx_string("auth_gss_authorized_principal"),
        SPNEGO_NGX_CONF_FLAGS | NGX_CONF_1MORE,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, auth_princs),
        NULL},

    {ngx_string("auth_gss_map_to_local"),
        SPNEGO_NGX_CONF_FLAGS,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, map_to_local),
        NULL},

    ngx_null_command
};

/* Module Context */
static ngx_http_module_t ngx_http_auth_spnego_module_ctx = {
    NULL, /* preconf */
    ngx_http_auth_spnego_init, /* postconf */
    NULL, /* create main conf (defaults) */
    NULL, /* init main conf (what's in nginx.conf) */
    NULL, /* create server conf */
    NULL, /* merge with main */

    ngx_http_auth_spnego_create_loc_conf, /* create location conf */
    ngx_http_auth_spnego_merge_loc_conf, /* merge with server */
};

/* Module Definition */
ngx_module_t ngx_http_auth_spnego_module = {
    /* ngx_uint_t ctx_index, index, spare{0-3}, version; */
    NGX_MODULE_V1, /* 0, 0, 0, 0, 0, 0, 1 */
    &ngx_http_auth_spnego_module_ctx, /* void *ctx */
    ngx_http_auth_spnego_commands, /* ngx_command_t *commands */
    NGX_HTTP_MODULE, /* ngx_uint_t type = 0x50545448 */
    NULL, /* ngx_int_t (*init_master)(ngx_log_t *log) */
    NULL, /* ngx_int_t (*init_module)(ngx_cycle_t *cycle) */
    NULL, /* ngx_int_t (*init_process)(ngx_cycle_t *cycle) */
    NULL, /* ngx_int_t (*init_thread)(ngx_cycle_t *cycle) */
    NULL, /* void (*exit_thread)(ngx_cycle_t *cycle) */
    NULL, /* void (*exit_process)(ngx_cycle_t *cycle) */
    NULL, /* void (*exit_master)(ngx_cycle_t *cycle) */
    NGX_MODULE_V1_PADDING, /* 0, 0, 0, 0, 0, 0, 0, 0 */
    /* uintptr_t spare_hook{0-7}; */
};

    static void *
ngx_http_auth_spnego_create_loc_conf(
        ngx_conf_t * cf)
{
    ngx_http_auth_spnego_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_spnego_loc_conf_t));
    if (NULL == conf) {
        return NGX_CONF_ERROR;
    }

    conf->protect = NGX_CONF_UNSET;
    conf->fqun = NGX_CONF_UNSET;
    conf->force_realm = NGX_CONF_UNSET;
    conf->allow_basic = NGX_CONF_UNSET;
    conf->auth_princs = NGX_CONF_UNSET_PTR;
    conf->map_to_local = NGX_CONF_UNSET;

    return conf;
}

    static char *
ngx_http_auth_spnego_merge_loc_conf(
        ngx_conf_t * cf,
        void *parent,
        void *child)
{
    ngx_http_auth_spnego_loc_conf_t *prev = parent;
    ngx_http_auth_spnego_loc_conf_t *conf = child;

    /* "off" by default */
    ngx_conf_merge_off_value(conf->protect, prev->protect, 0);

    ngx_conf_merge_str_value(conf->realm, prev->realm, "");
    ngx_conf_merge_str_value(conf->keytab, prev->keytab,
            "/etc/krb5.keytab");
    ngx_conf_merge_str_value(conf->srvcname, prev->srvcname, "");

    ngx_conf_merge_off_value(conf->fqun, prev->fqun, 0);
    ngx_conf_merge_off_value(conf->force_realm, prev->force_realm, 0);
    ngx_conf_merge_off_value(conf->allow_basic, prev->allow_basic, 1);
    ngx_conf_merge_ptr_value(conf->auth_princs, prev->auth_princs, NGX_CONF_UNSET_PTR);

    ngx_conf_merge_off_value(conf->map_to_local, prev->map_to_local, 0);

#if (NGX_DEBUG)
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: protect = %i",
            conf->protect);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: realm@0x%p = %s",
            conf->realm.data, conf->realm.data);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
            "auth_spnego: keytab@0x%p = %s", conf->keytab.data,
            conf->keytab.data);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
            "auth_spnego: srvcname@0x%p = %s",
            conf->srvcname.data, conf->srvcname.data);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: fqun = %i",
            conf->fqun);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: allow_basic = %i",
            conf->allow_basic);
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: force_realm = %i",
            conf->force_realm);
    if (NGX_CONF_UNSET_PTR != conf->auth_princs) {
        size_t ii = 0;
        ngx_str_t *auth_princs = conf->auth_princs->elts;
        for (; ii < conf->auth_princs->nelts; ++ii) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                    "auth_spnego: auth_princs = %.*s", auth_princs[ii].len, auth_princs[ii].data);
        }
    }
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "auth_spnego: map_to_local = %i",
            conf->map_to_local);
#endif

    return NGX_CONF_OK;
}

    static ngx_int_t
ngx_http_auth_spnego_init(
        ngx_conf_t * cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (NULL == h) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_spnego_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_spnego_headers_basic_only(
    ngx_http_request_t *r,
    ngx_http_auth_spnego_ctx_t *ctx,
    ngx_http_auth_spnego_loc_conf_t *alcf)
{
    ngx_str_t value = ngx_null_string;
    value.len = sizeof("Basic realm=\"\"") - 1 + alcf->realm.len;
    value.data = ngx_pcalloc(r->pool, value.len);
    if (NULL == value.data) {
        return NGX_ERROR;
    }
    ngx_snprintf(value.data, value.len, "Basic realm=\"%V\"",
            &alcf->realm);
    r->headers_out.www_authenticate =
        ngx_list_push(&r->headers_out.headers);
    if (NULL == r->headers_out.www_authenticate) {
        return NGX_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value.len = value.len;
    r->headers_out.www_authenticate->value.data = value.data;

    ctx->head = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_spnego_headers(
        ngx_http_request_t *r,
        ngx_http_auth_spnego_ctx_t *ctx,
        ngx_str_t *token,
        ngx_http_auth_spnego_loc_conf_t *alcf)
{
    ngx_str_t value = ngx_null_string;
    /* only use token if authorized as there appears to be a bug in
     * Google Chrome when parsing a 401 Negotiate with a token */
    if (NULL == token || ctx->ret != NGX_OK) {
        value.len = sizeof("Negotiate") - 1;
        value.data = (u_char *) "Negotiate";
    } else {
        value.len = sizeof("Negotiate") + token->len; /* space accounts for \0 */
        value.data = ngx_pcalloc(r->pool, value.len);
        if (NULL == value.data) {
            return NGX_ERROR;
        }
        ngx_snprintf(value.data, value.len, "Negotiate %V", token);
    }

    r->headers_out.www_authenticate =
        ngx_list_push(&r->headers_out.headers);
    if (NULL == r->headers_out.www_authenticate) {
        return NGX_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value.len = value.len;
    r->headers_out.www_authenticate->value.data = value.data;

    if (alcf->allow_basic) {
        ngx_str_t value2 = ngx_null_string;
        value2.len = sizeof("Basic realm=\"\"") - 1 + alcf->realm.len;
        value2.data = ngx_pcalloc(r->pool, value2.len);
        if (NULL == value2.data) {
            return NGX_ERROR;
        }
        ngx_snprintf(value2.data, value2.len, "Basic realm=\"%V\"",
                &alcf->realm);
        r->headers_out.www_authenticate =
            ngx_list_push(&r->headers_out.headers);
        if (NULL == r->headers_out.www_authenticate) {
            return NGX_ERROR;
        }

        r->headers_out.www_authenticate->hash = 2;
        r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
        r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
        r->headers_out.www_authenticate->value.len = value2.len;
        r->headers_out.www_authenticate->value.data = value2.data;
    }

    ctx->head = 1;

    return NGX_OK;
}

    static bool
ngx_spnego_authorized_principal(
        ngx_http_request_t * r,
        ngx_str_t *princ,
        ngx_http_auth_spnego_loc_conf_t *alcf)
{
    if (NGX_CONF_UNSET_PTR == alcf->auth_princs) {
        return true;
    }
    size_t ii = 0;
    ngx_str_t *auth_princs = alcf->auth_princs->elts;
    spnego_debug1("Testing against %d auth princs", alcf->auth_princs->nelts);
    for (; ii < alcf->auth_princs->nelts; ++ii) {
        if (auth_princs[ii].len != princ->len) {
            continue;
        }
        if (ngx_strncmp(auth_princs[ii].data, princ->data, princ->len) == 0) {
            spnego_debug2("Authorized user %.*s", princ->len, princ->data);
            return true;
        }
    }
    return false;
}

    ngx_int_t
ngx_http_auth_spnego_token(
        ngx_http_request_t *r,
        ngx_http_auth_spnego_ctx_t *ctx)
{
    ngx_str_t token;
    ngx_str_t decoded;
    size_t nego_sz = sizeof("Negotiate");

    if (NULL == r->headers_in.authorization) {
        return NGX_DECLINED;
    }

    /* but don't decode second time? */
    if (ctx->token.len)
        return NGX_OK;

    token = r->headers_in.authorization->value;

    if (token.len < nego_sz ||
            ngx_strncasecmp(token.data, (u_char *) "Negotiate ", nego_sz) != 0) {
        if (ngx_strncasecmp(
                    token.data, (u_char *) "NTLM", sizeof("NTLM")) == 0) {
            spnego_log_error("Detected unsupported mechanism: NTLM");
        }
        return NGX_DECLINED;
    }

    token.len -= nego_sz;
    token.data += nego_sz;

    while (token.len && token.data[0] == ' ') {
        token.len--;
        token.data++;
    }

    if (token.len == 0) {
        return NGX_DECLINED;
    }

    decoded.len = ngx_base64_decoded_length(token.len);
    decoded.data = ngx_pnalloc(r->pool, decoded.len);
    if (NULL == decoded.data) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded, &token) != NGX_OK) {
        return NGX_DECLINED;
    }

    ctx->token.len = decoded.len;
    ctx->token.data = decoded.data;
    spnego_debug2("Token decoded: %*s", token.len, token.data);

    return NGX_OK;
}

    ngx_int_t
ngx_http_auth_spnego_basic(
        ngx_http_request_t * r,
        ngx_http_auth_spnego_ctx_t * ctx,
        ngx_http_auth_spnego_loc_conf_t * alcf)
{
    ngx_str_t host_name;
    ngx_str_t service;
    ngx_str_t user;
    user.data = NULL;
    ngx_str_t new_user;
    ngx_int_t ret = NGX_DECLINED;

    krb5_context kcontext = NULL;
    krb5_error_code code;
    krb5_principal client = NULL;
    krb5_principal server = NULL;
    krb5_creds creds;
    krb5_get_init_creds_opt *gic_options = NULL;
    int kret = 0;
    char *name = NULL;
    char *p = NULL;

    code = krb5_init_context(&kcontext);
    if (code) {
        spnego_debug0("Kerberos error: Cannot initialize kerberos context");
        return NGX_ERROR;
    }

    host_name = r->headers_in.host->value;
    service.len = alcf->srvcname.len + alcf->realm.len + 3;

    if (ngx_strchr(alcf->srvcname.data, '/')) {
        service.data = ngx_palloc(r->pool, service.len);
        if (NULL == service.data) {
            spnego_error(NGX_ERROR);
        }

        ngx_snprintf(service.data, service.len, "%V@%V%Z",
                &alcf->srvcname, &alcf->realm);
    } else {
        service.len += host_name.len;
        service.data = ngx_palloc(r->pool, service.len);
        if (NULL == service.data) {
            spnego_error(NGX_ERROR);
        }

        ngx_snprintf(service.data, service.len, "%V/%V@%V%Z",
                &alcf->srvcname, &host_name, &alcf->realm);
    }

    kret = krb5_parse_name(kcontext, (const char *) service.data, &server);

    if (kret) {
        spnego_log_error("Kerberos error:  Unable to parse service name");
        spnego_log_krb5_error(kcontext, code);
        spnego_error(NGX_ERROR);
    }

    code = krb5_unparse_name(kcontext, server, &name);
    if (code) {
        spnego_log_error("Kerberos error: Cannot unparse servicename");
        spnego_log_krb5_error(kcontext, code);
        spnego_error(NGX_ERROR);
    }

    free(name);
    name = NULL;

    p = ngx_strchr(r->headers_in.user.data, '@');
    user.len = r->headers_in.user.len + 1;
    if (NULL == p) {
        if (alcf->force_realm && alcf->realm.len && alcf->realm.data ) {
            user.len += alcf->realm.len + 1; /* +1 for @ */
            user.data = ngx_palloc(r->pool, user.len);
            if (NULL == user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V@%V%Z", &r->headers_in.user,
                    &alcf->realm);
        } else {
            user.data = ngx_palloc(r->pool, user.len);
            if (NULL == user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
        }
    } else {
        if (alcf->realm.len && alcf->realm.data && ngx_strncmp(p + 1,
                    alcf->realm.data, alcf->realm.len) == 0) {
            user.data = ngx_palloc(r->pool, user.len);
            if (NULL == user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z",
                    &r->headers_in.user);
            if (alcf->fqun == 0) {
                /*
                 * Specified realm is identical to configured realm.
                 * Truncate $remote_user to strip @REALM.
                 */
                r->headers_in.user.len -= alcf->realm.len + 1;
            }
        } else if (alcf->force_realm) {
            *p = '\0';
            user.len = ngx_strlen(r->headers_in.user.data) + 1;
            if (alcf->realm.len && alcf->realm.data)
                user.len += alcf->realm.len + 1;
            user.data = ngx_pcalloc(r->pool, user.len);
            if (NULL == user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            if (alcf->realm.len && alcf->realm.data)
                ngx_snprintf(user.data, user.len, "%s@%V%Z",
                        r->headers_in.user.data, &alcf->realm);
            else
                ngx_snprintf(user.data, user.len, "%s%Z",
                        r->headers_in.user.data);
            /*
             * Rewrite $remote_user with the forced realm.
             * If the forced realm is shorter than the
             * specified realm, we can reuse the original
             * buffer.
             */
            if (r->headers_in.user.len >= user.len - 1)
                r->headers_in.user.len = user.len - 1;
            else {
                new_user.len = user.len - 1;
                new_user.data = ngx_palloc(r->pool, new_user.len);
                if (NULL == new_user.data) {
                    spnego_log_error("Not enough memory");
                    spnego_error(NGX_ERROR);
                }
                ngx_pfree(r->pool, r->headers_in.user.data);
                r->headers_in.user.data = new_user.data;
                r->headers_in.user.len = new_user.len;
            }
            ngx_memcpy(r->headers_in.user.data, user.data,
                    r->headers_in.user.len);
        } else {
            user.data = ngx_palloc(r->pool, user.len);
            if (NULL == user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
        }
    }

    spnego_debug1("Attempting authentication with principal %s",
            (const char *)user.data);

    code = krb5_parse_name(kcontext, (const char *) user.data, &client);
    if (code) {
        spnego_log_error("Kerberos error: Unable to parse username");
        spnego_debug1("username is %s.", (const char *) user.data);
        spnego_log_krb5_error(kcontext, code);
        spnego_error(NGX_ERROR);
    }

    memset(&creds, 0, sizeof(creds));

    code = krb5_unparse_name(kcontext, client, &name);
    if (code) {
        spnego_log_error("Kerberos error: Cannot unparse username");
        spnego_log_krb5_error(kcontext, code);
        spnego_error(NGX_ERROR);
    }

    krb5_get_init_creds_opt_alloc(kcontext, &gic_options);

    code = krb5_get_init_creds_password(kcontext, &creds, client,
                (char *) r->headers_in.passwd.data,
                NULL, NULL, 0, NULL, gic_options);

    krb5_free_cred_contents(kcontext, &creds);

    if (code) {
        spnego_log_error("Kerberos error: Credentials failed");
        spnego_log_krb5_error(kcontext, code);
        spnego_error(NGX_DECLINED);
    }

    /* Try to add the system realm to $remote_user if needed. */
    if (alcf->fqun && !ngx_strchr(r->headers_in.user.data, '@')) {
#ifdef krb5_princ_realm
        /*
         * MIT does not have krb5_principal_get_realm() but its
         * krb5_princ_realm() is a macro that effectively points
         * to a char *.
         */
        const char *realm = krb5_princ_realm(kcontext, client)->data;
#else
        const char *realm = krb5_principal_get_realm(kcontext, client);
#endif
        if (realm) {
            new_user.len = r->headers_in.user.len + 1 + ngx_strlen(realm);
            new_user.data = ngx_palloc(r->pool, new_user.len);
            if (NULL == new_user.data) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(new_user.data, new_user.len, "%V@%s",
                    &r->headers_in.user, realm);
            ngx_pfree(r->pool, r->headers_in.user.data);
            r->headers_in.user.data = new_user.data;
            r->headers_in.user.len = new_user.len;
        }
    }

    spnego_debug1("Setting $remote_user to %V", &r->headers_in.user);
    if (ngx_http_auth_spnego_set_bogus_authorization(r) != NGX_OK)
        spnego_log_error("Failed to set $remote_user");

    spnego_debug0("ngx_http_auth_spnego_basic: returning NGX_OK");

    ret = NGX_OK;

end:
    if (name)
        free(name);
    if (client)
        krb5_free_principal(kcontext, client);
    if (server)
        krb5_free_principal(kcontext, server);
    if (service.data)
        ngx_pfree(r->pool, service.data);
    if (user.data)
        ngx_pfree(r->pool, user.data);

    krb5_get_init_creds_opt_free(kcontext, gic_options);

    krb5_free_context(kcontext);

    return ret;
}


/*
 * Because 'remote_user' is assumed to be provided by basic authorization
 * (see ngx_http_variable_remote_user) we are forced to create bogus
 * non-Negotiate authorization header. This may possibly clobber Negotiate
 * token too soon.
 */
    ngx_int_t
ngx_http_auth_spnego_set_bogus_authorization(
        ngx_http_request_t *r)
{
    const char *bogus_passwd = "bogus_auth_gss_passwd";
    ngx_str_t plain, encoded, final;

    if (r->headers_in.user.len == 0) {
        spnego_debug0("ngx_http_auth_spnego_set_bogus_authorization: no user NGX_DECLINED");
        return NGX_DECLINED;
    }

    /* +1 because of the ":" in "user:password" */
    plain.len = r->headers_in.user.len + ngx_strlen(bogus_passwd) + 1;
    plain.data = ngx_pnalloc(r->pool, plain.len);
    if (NULL == plain.data) {
        return NGX_ERROR;
    }

    ngx_snprintf(plain.data, plain.len, "%V:%s",
            &r->headers_in.user, bogus_passwd);

    encoded.len = ngx_base64_encoded_length(plain.len);
    encoded.data = ngx_pnalloc(r->pool, encoded.len);
    if (NULL == encoded.data) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&encoded, &plain);

    final.len = sizeof("Basic ") + encoded.len - 1;
    final.data = ngx_pnalloc(r->pool, final.len);
    if (NULL == final.data) {
        return NGX_ERROR;
    }

    ngx_snprintf(final.data, final.len, "Basic %V", &encoded);

    /* WARNING clobbering authorization header value */
    r->headers_in.authorization->value.len = final.len;
    r->headers_in.authorization->value.data = final.data;

    spnego_debug0("ngx_http_auth_spnego_set_bogus_authorization: bogus user set");
    return NGX_OK;
}

    static bool
use_keytab(
        ngx_http_request_t * r,
        ngx_str_t *keytab)
{
    size_t kt_sz = keytab->len + 1;
    char *kt = (char *) ngx_pcalloc(r->pool, kt_sz);
    if (NULL == kt) {
        return false;
    }
    ngx_snprintf((u_char *) kt, kt_sz, "%V%Z", keytab);
    OM_uint32 major_status, minor_status = 0;
    major_status = gsskrb5_register_acceptor_identity(kt);
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s failed to register keytab", get_gss_error(
                    r->pool, minor_status,
                    "gsskrb5_register_acceptor_identity() failed"));
        return false;
    }

    spnego_debug1("Use keytab %V", keytab);
    return true;
}

    ngx_int_t
ngx_http_auth_spnego_auth_user_gss(
        ngx_http_request_t * r,
        ngx_http_auth_spnego_ctx_t * ctx,
        ngx_http_auth_spnego_loc_conf_t * alcf)
{
    ngx_int_t ret = NGX_DECLINED;
    u_char *pu;
    ngx_str_t spnego_token = ngx_null_string;
    OM_uint32 major_status, minor_status, minor_status2;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_name_t my_gss_name = GSS_C_NO_NAME;
    gss_cred_id_t my_gss_creds = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    if (NULL == ctx || ctx->token.len == 0)
        return ret;

    spnego_debug0("GSSAPI authorizing");

    if (!use_keytab(r, &alcf->keytab)) {
        spnego_debug0("Failed to specify keytab");
        spnego_error(NGX_ERROR);
    }

    if (alcf->srvcname.len > 0) {
        /* if there is a specific service prinicipal set in the configuration
         * file, we need to use it.  Otherwise, use the default of no credentials
         */
        service.length = alcf->srvcname.len + alcf->realm.len + 2;
        service.value = ngx_palloc(r->pool, service.length);
        if (NULL == service.value) {
            spnego_error(NGX_ERROR);
        }
        ngx_snprintf(service.value, service.length, "%V@%V%Z",
                &alcf->srvcname, &alcf->realm);

        spnego_debug1("Using service principal: %s", service.value);
        major_status = gss_import_name(&minor_status, &service,
                (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME, &my_gss_name);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s Used service principal: %s", get_gss_error(
                        r->pool, minor_status, "gss_import_name() failed"),
                    (u_char *) service.value);
            spnego_error(NGX_ERROR);
        }
        gss_buffer_desc human_readable_gss_name = GSS_C_EMPTY_BUFFER;
        major_status = gss_display_name(&minor_status, my_gss_name,
                &human_readable_gss_name, NULL);

        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s Used service principal: %s ", get_gss_error(
                        r->pool, minor_status, "gss_display_name() failed"),
                    (u_char *) service.value);
        }
        spnego_debug1("my_gss_name %s", human_readable_gss_name.value);

        /* Obtain credentials */
        major_status = gss_acquire_cred(&minor_status, my_gss_name,
                GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &my_gss_creds,
                NULL, NULL);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s Used service principal: %s", get_gss_error(
                        r->pool, minor_status, "gss_acquire_cred() failed"),
                    (u_char *) service.value);
            spnego_error(NGX_ERROR);
        }

    }

    input_token.length = ctx->token.len;
    input_token.value = (void *) ctx->token.data;

    major_status = gss_accept_sec_context(&minor_status, &gss_context,
            my_gss_creds, &input_token, GSS_C_NO_CHANNEL_BINDINGS, &client_name,
            NULL, &output_token, NULL, NULL, NULL);
    if (GSS_ERROR(major_status)) {
        spnego_debug1("%s", get_gss_error(
                    r->pool, minor_status, "gss_accept_sec_context() failed"));
        spnego_error(NGX_DECLINED);
    }

    if (major_status & GSS_S_CONTINUE_NEEDED) {
        spnego_debug0("only one authentication iteration allowed");
        spnego_error(NGX_DECLINED);
    }

    if (output_token.length) {
        spnego_token.data = (u_char *) output_token.value;
        spnego_token.len = output_token.length;

        ctx->token_out_b64.len = ngx_base64_encoded_length(spnego_token.len);
        ctx->token_out_b64.data = ngx_pcalloc(r->pool, ctx->token_out_b64.len + 1);
        if (NULL == ctx->token_out_b64.data) {
            spnego_log_error("Not enough memory");
            gss_release_buffer(&minor_status2, &output_token);
            spnego_error(NGX_ERROR);
        }
        ngx_encode_base64(&ctx->token_out_b64, &spnego_token);
        gss_release_buffer(&minor_status2, &output_token);
    }
	else {
        ctx->token_out_b64.len = 0;
	}

    /* getting user name at the other end of the request */
    major_status = gss_display_name(&minor_status, client_name, &output_token, NULL);
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s", get_gss_error(r->pool, minor_status,
                    "gss_display_name() failed"));
        spnego_error(NGX_ERROR);
    }

    if (output_token.length) {
        /* Apply local rules to map Kerberos Principals to short names */
        if (alcf->map_to_local) {
            gss_OID mech_type = discard_const(gss_mech_krb5);
            output_token = (gss_buffer_desc) GSS_C_EMPTY_BUFFER;
            major_status = gss_localname(&minor_status, client_name,
                    mech_type, &output_token);
            if (GSS_ERROR(major_status)) {
                spnego_log_error("%s", get_gss_error(r->pool, minor_status,
                            "gss_localname() failed"));
                spnego_error(NGX_ERROR);
            }
        }

        /* TOFIX dirty quick trick for now (no "-1" i.e. include '\0' */
        ngx_str_t user = {
            output_token.length,
            (u_char *) output_token.value
        };

        r->headers_in.user.data = ngx_pstrdup(r->pool, &user);
        if (NULL == r->headers_in.user.data) {
            spnego_log_error("ngx_pstrdup failed to allocate");
            spnego_error(NGX_ERROR);
        }

        r->headers_in.user.len = user.len;
        if (alcf->fqun == 0) {
            pu = ngx_strlchr(r->headers_in.user.data,
                    r->headers_in.user.data + r->headers_in.user.len, '@');
            if (pu != NULL && ngx_strncmp(pu + 1, alcf->realm.data, alcf->realm.len) == 0) {
                *pu = '\0';
                r->headers_in.user.len = ngx_strlen(r->headers_in.user.data);
            }
        }

        /* this for the sake of ngx_http_variable_remote_user */
        if (ngx_http_auth_spnego_set_bogus_authorization(r) != NGX_OK) {
            spnego_log_error("Failed to set remote_user");
        }
        spnego_debug1("user is %V", &r->headers_in.user);
    }

    gss_release_buffer(&minor_status, &output_token);

    ret = NGX_OK;
    goto end;

end:
    if (output_token.length)
        gss_release_buffer(&minor_status, &output_token);

    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &client_name);

    if (gss_context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status, &gss_context,
                GSS_C_NO_BUFFER);

    if (my_gss_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &my_gss_name);

    if (my_gss_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &my_gss_creds);

    return ret;
}

    static ngx_int_t
ngx_http_auth_spnego_handler(
        ngx_http_request_t * r)
{
    ngx_int_t ret = NGX_DECLINED;
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_auth_spnego_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_spnego_module);

    if (alcf->protect == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_spnego_module);
    if (NULL == ctx) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_auth_spnego_ctx_t));
        if (NULL == ctx) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->token.len = 0;
        ctx->token.data = NULL;
        ctx->head = 0;
        ctx->ret = NGX_HTTP_UNAUTHORIZED;
        ngx_http_set_ctx(r, ctx, ngx_http_auth_spnego_module);
    }

    spnego_debug3("SSO auth handling IN: token.len=%d, head=%d, ret=%d",
            ctx->token.len, ctx->head, ctx->ret);

    if (ctx->token.len && ctx->head) {
        spnego_debug1("Found token and head, returning %d", ctx->ret);
        return ctx->ret;
    }

    if (NULL != r->headers_in.user.data) {
        spnego_debug0("User header set");
        return NGX_OK;
    }

    spnego_debug0("Begin auth");

    if (alcf->allow_basic) {
        spnego_debug0("Detect basic auth");
        ret = ngx_http_auth_basic_user(r);
        if (NGX_OK == ret) {
            spnego_debug0("Basic auth credentials supplied by client");
            /* If basic auth is enabled and basic creds are supplied
             * attempt basic auth.  If we attempt basic auth, we do
             * not fall through to real SPNEGO */
            if (NGX_OK != ngx_http_auth_spnego_basic(r, ctx, alcf)) {
                spnego_debug0("Basic auth failed");
                if (NGX_ERROR == ngx_http_auth_spnego_headers_basic_only(r, ctx, alcf)) {
                    spnego_debug0("Error setting headers");
                    return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
                }
                return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
            }

            if (!ngx_spnego_authorized_principal(r, &r->headers_in.user, alcf)) {
                spnego_debug0("User not authorized");
                return (ctx->ret = NGX_HTTP_FORBIDDEN);
            }

            spnego_debug0("Basic auth succeeded");
            return (ctx->ret = NGX_OK);
        }
    }

    /* Basic auth either disabled or not supplied by client */
    spnego_debug0("Detect SPNEGO token");
    ret = ngx_http_auth_spnego_token(r, ctx);
    if (NGX_OK == ret) {
        spnego_debug0("Client sent a reasonable Negotiate header");
        ret = ngx_http_auth_spnego_auth_user_gss(r, ctx, alcf);
        if (NGX_ERROR == ret) {
            spnego_debug0("GSSAPI failed");
            return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        /* There are chances that client knows about Negotiate
         * but doesn't support GSSAPI. We could attempt to fall
         * back to basic here... */
        if (NGX_DECLINED == ret) {
            spnego_debug0("GSSAPI failed");
            if(!alcf->allow_basic) {
                return (ctx->ret = NGX_HTTP_FORBIDDEN);
            }
            if (NGX_ERROR == ngx_http_auth_spnego_headers_basic_only(r, ctx, alcf)) {
                spnego_debug0("Error setting headers");
                return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
        }

        if (!ngx_spnego_authorized_principal(r, &r->headers_in.user, alcf)) {
            spnego_debug0("User not authorized");
            return (ctx->ret = NGX_HTTP_FORBIDDEN);
        }

        spnego_debug0("GSSAPI auth succeeded");
    }

    ngx_str_t *token_out_b64 = NULL;
    switch(ret) {
        case NGX_DECLINED: /* DECLINED, but not yet FORBIDDEN */
            ctx->ret = NGX_HTTP_UNAUTHORIZED;
            break;
        case NGX_OK:
            ctx->ret = NGX_OK;
            token_out_b64 = &ctx->token_out_b64;
            break;
        case NGX_ERROR:
        default:
            ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    if (NGX_ERROR == ngx_http_auth_spnego_headers(r, ctx, token_out_b64, alcf)) {
        spnego_debug0("Error setting headers");
        ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    spnego_debug3("SSO auth handling OUT: token.len=%d, head=%d, ret=%d",
            ctx->token.len, ctx->head, ctx->ret);
    return ctx->ret;
}
