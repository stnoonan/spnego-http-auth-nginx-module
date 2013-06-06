/*
 * Copyright (C) 2009 Michal Kowalski <superflouos{at}gmail[dot]com>
 * Copyright (C) 2012 Sean Timothy Noonan <stnoonan@obsolescence.net>
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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#define krb5_get_err_text(context,code) error_message(code)
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

    /* %Z inserts '\0' */
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

    /* "include" '\0' */
    str.len = len + 1;
    str.data = (u_char *) buf;
    return (char *) (ngx_pstrdup(p, &str));
}

/* Module per Req/Con CONTEXTUAL Struct */
typedef struct {
    ngx_str_t token; /* decoded Negotiate token */
    ngx_int_t head; /* non-zero flag if headers set */
    ngx_int_t ret; /* current return code */
} ngx_http_auth_spnego_ctx_t;

/* Module Configuration Struct(s) (main|srv|loc) */
typedef struct {
    ngx_flag_t protect;
    ngx_str_t realm;
    ngx_str_t keytab;
    ngx_str_t srvcname;
    ngx_str_t hostname;
    ngx_flag_t fqun;
    ngx_flag_t force_realm;
} ngx_http_auth_spnego_loc_conf_t;

/* Module Directives */
static ngx_command_t ngx_http_auth_spnego_commands[] = {
    {ngx_string("auth_gss"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, protect),
        NULL},

    {ngx_string("auth_gss_realm"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, realm),
        NULL},

    {ngx_string("auth_gss_keytab"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, keytab),
        NULL},

    {ngx_string("auth_gss_service_name"),
        /* TODO change to NGX_CONF_1MORE for "http", "khttp", besides "HTTP" */
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, srvcname),
        NULL},

    {ngx_string("auth_gss_host_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, hostname),
        NULL },

    {ngx_string("auth_gss_format_full"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, fqun),
        NULL},

    {ngx_string("auth_gss_force_realm"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_spnego_loc_conf_t, force_realm),
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

    ngx_conf_merge_str_value(conf->realm, prev->realm, "LOCALDOMAIN");
    ngx_conf_merge_str_value(conf->keytab, prev->keytab,
            "/etc/krb5.keytab");
    ngx_conf_merge_str_value(conf->srvcname, prev->srvcname, "HTTP");
    ngx_conf_merge_str_value(conf->hostname, prev->hostname, "");

    ngx_conf_merge_off_value(conf->fqun, prev->fqun, 0);
    ngx_conf_merge_off_value(conf->force_realm, prev->force_realm, 0);

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
ngx_http_auth_spnego_negotiate_headers(
    ngx_http_request_t *r,
    ngx_http_auth_spnego_ctx_t *ctx,
    ngx_str_t *token,
    ngx_http_auth_spnego_loc_conf_t *alcf,
    int negotiate)
{
    ngx_str_t value = ngx_null_string;

    if (negotiate) {
        if (NULL == token) {
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
        r->headers_out.www_authenticate->key.len =
            sizeof("WWW-Authenticate") - 1;
        r->headers_out.www_authenticate->key.data =
            (u_char *) "WWW-Authenticate";

        r->headers_out.www_authenticate->value.len = value.len;
        r->headers_out.www_authenticate->value.data = value.data;
    }

    /* Basic auth */
    if (NULL == token) {
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

        r->headers_out.www_authenticate->hash = 1;
        r->headers_out.www_authenticate->key.len =
            sizeof("WWW-Authenticate") - 1;
        r->headers_out.www_authenticate->key.data =
            (u_char *) "WWW-Authenticate";
        r->headers_out.www_authenticate->value.len = value2.len;
        r->headers_out.www_authenticate->value.data = value2.data;
    }

    ctx->head = 1;

    return NGX_OK;
}

ngx_int_t
ngx_http_auth_spnego_token(
    ngx_http_request_t *r,
    ngx_http_auth_spnego_ctx_t *ctx)
{
    ngx_str_t token;
    ngx_str_t decoded;

    if (NULL == r->headers_in.authorization) {
        return NGX_DECLINED;
    }
    /* but don't decode second time? */
    if (ctx->token.len)
        return NGX_OK;

    token = r->headers_in.authorization->value;

    if (token.len < sizeof("Negotiate ") - 1
            || ngx_strncasecmp(token.data, (u_char *) "Negotiate ",
                sizeof("Negotiate ") - 1) != 0) {
        return NGX_DECLINED;
    }

    token.len -= sizeof("Negotiate ") - 1;
    token.data += sizeof("Negotiate ") - 1;

    while (token.len && token.data[0] == ' ') {
        token.len--;
        token.data++;
    }

    if (token.len == 0) {
        return NGX_DECLINED;
    }

    decoded.len = ngx_base64_decoded_length(token.len);
    decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
    if (NULL == decoded.data) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded, &token) != NGX_OK) {
        return NGX_DECLINED;
    }

    decoded.data[decoded.len] = '\0'; /* hmmm */

    ctx->token.len = decoded.len;
    ctx->token.data = decoded.data;
    spnego_debug1("Token decoded: %s", token.data);

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
    int len;

    ngx_int_t ret = NGX_DECLINED;

    krb5_context kcontext = NULL;
    krb5_error_code code;
    krb5_principal client = NULL;
    krb5_principal server = NULL;
    krb5_creds creds;
    krb5_get_init_creds_opt gic_options;
    int kret = 0;
    char *name = NULL;
    char *p = NULL;
    u_char *new_user=NULL;

    code = krb5_init_context(&kcontext);
    if (code) {
        spnego_debug0("Kerberos error: Cannot initialize kerberos context");
        return NGX_ERROR;
    }

    /* TODO: support nonstandard ports */
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
        spnego_log_error("Kerberos error:", krb5_get_err_text(kcontext, code));
        spnego_error(NGX_ERROR);
    }

    code = krb5_unparse_name(kcontext, server, &name);
    if (code) {
        spnego_log_error("Kerberos error: Cannot unparse servicename");
        spnego_log_error("Kerberos error:", krb5_get_err_text(kcontext, code));
        spnego_error(NGX_ERROR);
    }

    free(name);
    name = NULL;

    p = ngx_strchr(r->headers_in.user.data, '@');
    user.len = r->headers_in.user.len + 1;
    if (NULL == p) {
        user.len += alcf->realm.len + 1;
        user.data = ngx_palloc(r->pool, user.len);
        ngx_snprintf(user.data, user.len, "%V@%V%Z", &r->headers_in.user,
                &alcf->realm);
        if (alcf->force_realm && alcf->realm.data){
            len = user.len + 1;
            new_user = ngx_pcalloc(r->pool, len);
            if (NULL == new_user) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_sprintf(new_user, "%s", user.data);
            new_user[len-1] = '\0';
            r->headers_in.user.len = len;
            ngx_pfree(r->pool, r->headers_in.user.data);
            r->headers_in.user.data = new_user;
            spnego_debug1("set user to %s", new_user);
            ngx_http_auth_spnego_set_bogus_authorization(r);
        }
    } else {
        user.data = ngx_palloc(r->pool, user.len);
        ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
        if(alcf->force_realm && alcf->realm.data){
            p = ngx_strchr(user.data,'@');
            if (ngx_strcmp(p + 1, alcf->realm.data) != 0) {
                *p = '\0';
                len = user.len + 2 + alcf->realm.len;
                new_user = ngx_pcalloc(r->pool, len);
                if (NULL == new_user) {
                    spnego_log_error("Not enough memory");
                    spnego_error(NGX_ERROR);
                }
                ngx_sprintf(new_user,"%s@%s%Z",user.data,alcf->realm.data);
                new_user[len-1] = '\0';
                r->headers_in.user.len = len;
                ngx_pfree(r->pool, r->headers_in.user.data);
                r->headers_in.user.data = new_user;
                spnego_debug2("set user to %s, realm %s included", new_user, alcf->realm.data);
                ngx_http_auth_spnego_set_bogus_authorization(r);
                spnego_debug1("after bogus authorization user.data is %s", (const char *) user.data);
            }
        }
    }
    spnego_debug1("before krb5_parse_name user.data is %s", (const char *) user.data);
    code = krb5_parse_name(kcontext, (const char *) user.data, &client);

    if (code) {
        spnego_log_error("Kerberos error: Unable to parse username");
        spnego_debug1("username is %s.", (const char *) user.data);
        spnego_log_error("Kerberos error:", krb5_get_err_text(kcontext, code));
        spnego_error(NGX_ERROR);
    }

    memset(&creds, 0, sizeof(creds));

    code = krb5_unparse_name(kcontext, client, &name);
    if (code) {
        spnego_log_error("Kerberos error: Cannot unparse username");
        spnego_log_error("Kerberos error:", krb5_get_err_text(kcontext, code));
        spnego_error(NGX_ERROR);
    }

    krb5_get_init_creds_opt_init(&gic_options);

    code =
        krb5_get_init_creds_password(kcontext, &creds, client,
                (char *) r->headers_in.passwd.data,
                NULL, NULL, 0, NULL, &gic_options);

    krb5_free_cred_contents(kcontext, &creds);

    if (code) {
        spnego_log_error("Kerberos error: Credentials failed");
        spnego_log_error("Kerberos error:", krb5_get_err_text(kcontext, code));
        spnego_error(NGX_HTTP_UNAUTHORIZED);
    }
    spnego_debug0("ngx_http_auth_spnego_basic: returning NGX_OK");

    ret = NGX_OK;

end:
    if (name)
        free(name);
    if (client)
        krb5_free_principal(kcontext, client);
    if (server)
        krb5_free_principal(kcontext, server);
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
    ngx_str_t plain, encoded, final;

    if (r->headers_in.user.len == 0) {
        return NGX_DECLINED;
    }

    /* including \0 from sizeof because it's "user:password" */
    plain.len = r->headers_in.user.len + sizeof("bogus");
    plain.data = ngx_pnalloc(r->pool, plain.len);
    if (NULL == plain.data) {
        return NGX_ERROR;
    }

    ngx_snprintf(plain.data, plain.len, "%V:bogus", &r->headers_in.user);

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

    return NGX_OK;
}

ngx_int_t
ngx_http_auth_spnego_auth_user_gss(
    ngx_http_request_t * r,
    ngx_http_auth_spnego_ctx_t * ctx,
    ngx_http_auth_spnego_loc_conf_t * alcf)
{
    /* nginx stuff */
    ngx_str_t host_name;
    ngx_int_t ret = NGX_DECLINED;
    char *p;

    /* kerberos stuff */
    krb5_context krb_ctx = NULL;
    char *ktname = NULL;
    ngx_str_t spnegoToken = ngx_null_string;

    /* gssapi stuff */
    OM_uint32 major_status, minor_status, minor_status2;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_name_t my_gss_name = GSS_C_NO_NAME;
    gss_cred_id_t my_gss_creds = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret_flags = 0;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;

    if (NULL == ctx || ctx->token.len == 0)
        return ret;

    spnego_debug0("GSSAPI authorizing");

    krb5_init_context(&krb_ctx);

    ktname = (char *) ngx_pcalloc(r->pool, sizeof("KRB5_KTNAME=") +
            alcf->keytab.len + 1);
    if (NULL == ktname) {
        spnego_error(NGX_ERROR);
    }
    ngx_snprintf((u_char *) ktname,
            sizeof("KRB5_KTNAME=") + alcf->keytab.len,
            "KRB5_KTNAME=%V%Z", &alcf->keytab);
    putenv(ktname);

    spnego_debug1("Use keytab %V", &alcf->keytab);

    /* Use the SPN as expected by the client assuming HTTP/http_host */
    host_name = r->headers_in.host->value;
    service.length = alcf->srvcname.len + alcf->realm.len + 3;

    u_char *port_start = (u_char *) ngx_strchr(host_name.data, ':');
    if (NULL == port_start) { /* no port number specified */
        service.length += host_name.len;
    } else {/* port number included, strip it */
        service.length += port_start - host_name.data - 1;
    }

    if (ngx_strchr(alcf->srvcname.data, '/')) {
        service.value = ngx_palloc(r->pool, service.length);
        if (NULL == service.value) {
            spnego_error(NGX_ERROR);
        }

        ngx_snprintf(service.value, service.length, "%V@%V%Z",
                &alcf->srvcname, &alcf->realm);
    } else {
        service.length += host_name.len;
        service.value = ngx_palloc(r->pool, service.length);
        if (NULL == service.value) {
            spnego_error(NGX_ERROR);
        }

        ngx_snprintf(service.value, service.length, "%V/%V@%V%Z",
                &alcf->srvcname, &host_name, &alcf->realm);
    }
    spnego_debug1("Using service principal: %s", service.value);

    major_status = gss_import_name(&minor_status, &service,
            (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
            &my_gss_name);
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s Used service principal: %s", get_gss_error(
                    r->pool, minor_status, "gss_import_name() failed"),
                (u_char *) service.value);
        spnego_error(NGX_ERROR);
    }

    /* Log the credentials we plan to use */
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
    major_status =
        gss_acquire_cred(&minor_status, my_gss_name, GSS_C_INDEFINITE,
                GSS_C_NO_OID_SET, GSS_C_ACCEPT, &my_gss_creds,
                NULL, NULL);
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s Used service principal: %s", get_gss_error(
                    r->pool, minor_status, "gss_acquire_cred() failed"),
                (u_char *) service.value);
        spnego_error(NGX_ERROR);
    }

    /* Decode the tokens as needed to support SPNEGO and GSS Negotiate */
    input_token.length = ctx->token.len;
    input_token.value = (void *) ctx->token.data;

    major_status = gss_accept_sec_context(&minor_status, &gss_context,
            my_gss_creds, &input_token, GSS_C_NO_CHANNEL_BINDINGS, &client_name,
            NULL, &output_token, &ret_flags, NULL, &delegated_cred);
    if (GSS_ERROR(major_status)) {
        spnego_debug3("%s Used service principal: %s, input token: %s", get_gss_error(r->pool,
                    minor_status, "gss_accept_sec_context() failed"),
                (u_char *) service.value, (u_char *) input_token.value);
        spnego_error(NGX_DECLINED);
    }

    if (major_status & GSS_S_CONTINUE_NEEDED) {
        spnego_debug0("only one authentication iteration allowed");
        spnego_error(NGX_DECLINED);
    }

    if (output_token.length) {
        ngx_str_t token = ngx_null_string;

        spnegoToken.data = (u_char *) output_token.value;
        spnegoToken.len = output_token.length - 1;

        token.len = ngx_base64_encoded_length(spnegoToken.len);
        token.data = ngx_pcalloc(r->pool, token.len + 1);
        if (NULL == token.data) {
            spnego_log_error("Not enough memory");
            gss_release_buffer(&minor_status2, &output_token);
            spnego_error(NGX_ERROR);
        }
        ngx_encode_base64(&token, &spnegoToken);
        gss_release_buffer(&minor_status2, &output_token);

        /* rework ngx_http_auth_spnego_negotiate_headers... */
        if (ngx_http_auth_spnego_negotiate_headers(r, ctx, &token, alcf, 1)
                == NGX_ERROR) {
            spnego_error(NGX_ERROR);
        }
    }

    if (!(ret_flags & GSS_C_REPLAY_FLAG || ret_flags & GSS_C_SEQUENCE_FLAG)) {
        spnego_debug0("GSSAPI Warning: no replay protection !");
    }
    if (!(ret_flags & GSS_C_SEQUENCE_FLAG)) {
        spnego_debug0("GSSAPI Warning: no sequence protection !");
    }

    /* getting user name at the other end of the request */
    major_status =
        gss_display_name(&minor_status, client_name, &output_token, NULL);
    gss_release_name(&minor_status, &client_name);

    /* hmm... if he is going to ERROR out now we should do it before setting headers... */
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s", get_gss_error(r->pool, minor_status,
                    "gss_display_name() failed"));
        spnego_error(NGX_ERROR);
    }

    if (output_token.length) {
        /* TOFIX dirty quick trick for now (no "-1" i.e. include '\0' */
        ngx_str_t user = {
            output_token.length,
            (u_char *) output_token.value
        };

        r->headers_in.user.data = ngx_pstrdup(r->pool, &user);
        /* NULL?!? */
        r->headers_in.user.len = user.len;
        if (alcf->fqun == 0) {
            p = ngx_strchr(r->headers_in.user.data, '@');
            if (p != NULL && ngx_strcmp(p + 1, alcf->realm.data) == 0) {
                *p = '\0';
                r->headers_in.user.len = ngx_strlen(r->headers_in.user.data);
            }
        }

        /* this for the sake of ngx_http_variable_remote_user */
        ngx_http_auth_spnego_set_bogus_authorization(r);
        spnego_debug1("user is %V", &r->headers_in.user);
    }

    gss_release_buffer(&minor_status, &output_token);

    /* saving creds... LATER, for now debug msg... */
    if (delegated_cred != GSS_C_NO_CREDENTIAL) {
        spnego_debug0("Had delegated_cred to save.");
    }

    ret = NGX_OK;
    goto end;

end:
    if (delegated_cred)
        gss_release_cred(&minor_status, &delegated_cred);

    if (output_token.length)
        gss_release_buffer(&minor_status, &output_token);

    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &client_name);

    if (gss_context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status, &gss_context,
                GSS_C_NO_BUFFER);

    krb5_free_context(krb_ctx);
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
    ngx_int_t ret;
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
    /* nope... local fs req creates new ctx... useless... */

    spnego_debug3("SSO auth handling IN: token.len=%d, head=%d, ret=%d",
            ctx->token.len, ctx->head, ctx->ret);

    if (ctx->token.len && ctx->head)
        return ctx->ret;
    if (r->headers_in.user.data != NULL)
        return NGX_OK;

    ret = ngx_http_auth_basic_user(r);
    if (ret == NGX_OK) {
        /* Got some valid auth_basic data */
        ctx->ret = ngx_http_auth_spnego_basic(r, ctx, alcf);
        spnego_debug1("ngx_http_auth_spnego_handler: returning %d", ctx->ret);
        /* If we got a 401, we should send back headers. */
        if (ctx->ret == NGX_HTTP_UNAUTHORIZED) {
            spnego_debug0("Sending 401 => repeat headers.");
            ret = ngx_http_auth_spnego_negotiate_headers(r, ctx, NULL, alcf, 0);
            if (ret == NGX_ERROR) {
                return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
        }
        return ctx->ret;
    } else {
        ret = ngx_http_auth_spnego_token(r, ctx);
    }

    if (ret == NGX_OK) {
        /* client sent some Negotiate'ing authorization header... */
        ret = ngx_http_auth_spnego_auth_user_gss(r, ctx, alcf);
        /* There are chances that client knows about Negotiate but doesn't support GSSAPI */
        if (ret == NGX_DECLINED) {
            spnego_debug0("GSSAPI failed. Retrying basic auth.");
            ret = ngx_http_auth_spnego_negotiate_headers(r, ctx, NULL, alcf, 0);
            if (ret == NGX_ERROR) {
                return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
        }
    }

    if (ret == NGX_DECLINED) {
        /* TODEBATE skip if (ctx->head)... */
        ret = ngx_http_auth_spnego_negotiate_headers(r, ctx, NULL, alcf, 1);
        if (ret == NGX_ERROR) {
            return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
    }

    if (ret == NGX_ERROR) {
        return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    /* else NGX_OK */
    spnego_debug3("SSO auth handling OUT: token.len=%d, head=%d, ret=%d",
            ctx->token.len, ctx->head, ret);
    return (ctx->ret = ret);
}
