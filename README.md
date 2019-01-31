Nginx module for HTTP SPNEGO auth
=================================

This module implements adds [SPNEGO](http://tools.ietf.org/html/rfc4178)
support to nginx(http://nginx.org).  It currently supports only Kerberos
authentication via [GSSAPI](http://en.wikipedia.org/wiki/GSSAPI)


Prerequisites
-------------

Authentication has been tested with (at least) the following:

* Nginx 1.2 through 1.7
* Internet Explorer 8 and above
* Firefox 10 and above
* Chrome 20 and above
* Curl 7.x (GSS-Negotiate), 7.x (SPNEGO/fbopenssl)

The underlying kerberos library used for these tests was MIT KRB5 v1.8.


Installation
------------

1. Download [nginx source](http://www.nginx.org/en/download.html)
1. Extract to a directory
1. Clone this module into the directory
1. Follow the [nginx install documentation](http://nginx.org/en/docs/install.html)
and pass an `--add-module` option to nginx configure:

    ./configure --add-module=spnego-http-auth-nginx-module

Note that if it isn't clear, you do need KRB5 (MIT or Heimdal) header files installed.  On Debian based distributions, including Ubuntu, this is the krb5-multidev, libkrb5-dev, heimdal-dev, or heimdal-multidev package depending on your environment.  On other Linux distributions, you want the development libraries that provide gssapi_krb5.h.

Configuration reference
-----------------------

You can configure GSS authentication on a per-location and/or a global basis:

These options are required.
* `auth_gss`: on/off, for ease of unsecuring while leaving other options in
  the config file
* `auth_gss_keytab`: absolute path-name to keytab file containing service
  credentials

These options should ONLY be specified if you have a keytab containing
privileged principals.  In nearly all cases, you should not put these
in the configuration file, as `gss_accept_sec_context` will do the right
thing.
* `auth_gss_realm`: Kerberos realm name.  If this is specified, the realm is only passed to the nginx variable $remote_user if it differs from this default.  To override this behavior, set *auth_gss_format_full* to 1 in your configuration.
* `auth_gss_service_name`: service principal name to use when acquiring
  credentials.

If you would like to authorize only a specific set of users, you can use the
`auth_gss_authorized_principal` directive.  The configuration syntax supports
multiple entries, one per line.

    auth_gss_authorized_principal <username>@<realm>
    auth_gss_authorized_principal <username2>@<realm>

The remote user header in nginx can only be set by doing basic authentication.
Thus, this module sets a bogus basic auth header that will reach your backend
application in order to set this header/nginx variable.  The easiest way to disable
this behavior is to add the following configuration to your location config.

    proxy_set_header Authorization "";
    
A future version of the module may make this behavior an option, but this should
be a sufficient workaround for now.

If you would like to enable GSS local name rules to rewrite usernames, you can
specify the `auth_gss_map_to_local` option.

Basic authentication fallback
-----------------------------

The module falls back to basic authentication by default if no negotiation is
attempted by the client.  If you are using SPNEGO without SSL, it is recommended
you disable basic authentication fallback, as the password would be sent in
plaintext.  This is done by setting `auth_gss_allow_basic_fallback` in the
config file.

    auth_gss_allow_basic_fallback off

These options affect the operation of basic authentication:
* `auth_gss_realm`: Kerberos realm name.  If this is specified, the realm is
  only passed to the nginx variable $remote_user if it differs from this
  default.  To override this behavior, set *auth_gss_format_full* to 1 in your
  configuration.
* `auth_gss_force_realm`: Forcibly authenticate using the realm configured in
  `auth_gss_realm` or the system default realm if `auth_gss_realm` is not set.
  This will rewrite $remote_user if the client provided a different realm.  If
  *auth_gss_format_full* is not set, $remote_user will not include a realm even
  if one was specified by the client.


Troubleshooting
---------------

###
Check the logs.  If you see a mention of NTLM, your client is attempting to
connect using [NTLMSSP](http://en.wikipedia.org/wiki/NTLMSSP), which is
unsupported and insecure.

### Verify that you have an HTTP principal in your keytab ###

#### MIT Kerberos utilities ####

    $ KRB5_KTNAME=FILE:<path to your keytab> klist -k

or

    $ ktutil
    ktutil: read_kt <path to your keytab>
    ktutil: list

#### Heimdal Kerberos utilities ####

    $ ktutil -k <path to your keytab> list

### Obtain an HTTP principal

If you find that you do not have the HTTP service principal,
are running in an Active Directory environment,
and are bound to the domain such that Samba tools work properly

    $ env KRB5_KTNAME=FILE:<path to your keytab> net ads -P keytab add HTTP

If you are running in a different kerberos environment, you can likely run

    $ env KRB5_KTNAME=FILE:<path to your keytab> krb5_keytab HTTP

### Increase maximum allowed header size

In Active Directory environment, SPNEGO token in the Authorization header includes
PAC (Privilege Access Certificate) information, which includes all security groups
the user belongs to. This may cause the header to grow beyond default 8kB limit and
causes following error message:

    400 Bad Request
    Request Header Or Cookie Too Large

For performance reasons, best solution is to reduce the number of groups the user
belongs to. When this is impractical, you may also choose to increase the allowed
header size by explicitly setting the number and size of Nginx header buffers:

    large_client_header_buffers 8 32k;

Debugging
---------

The module prints all sort of debugging information if nginx is compiled with
the `--with-debug` option, and the `error_log` directive has a `debug` level.


NTLM
----

Note that the module does not support [NTLMSSP](http://en.wikipedia.org/wiki/NTLMSSP)
in Negotiate. NTLM, both v1 and v2, is an exploitable protocol and should be avoided
where possible.

Help
----

If you're unable to figure things out, please feel free to open an 
issue on Github and I'll do my best to help you.
