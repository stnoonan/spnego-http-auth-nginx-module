Nginx module for HTTP SPNEGO auth
=================================

This module implements adds [SPNEGO](http://tools.ietf.org/html/rfc4178)
support to nginx(http://nginx.org).  It currently supports only Kerberos
authentication via [GSSAPI](http://en.wikipedia.org/wiki/GSSAPI)

Purpose of this fork
--------------------

This fork is abandoned. Please use the original source: http://github.com/stnoonan/spnego-http-auth-nginx-module

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

Ubuntu 12.04 LTS packages for the latest version of Nginx compiled with the SPNEGO module
are [available in this PPA](https://launchpad.net/~bcandrea/+archive/nginx-stable).


Crash course to Windows KDC Configuration
-----------------------------------------

On the AD side, you need to:

* Create a new user, whose name should be the service name you'll be using
  Kerberos authentication on. E.g. `app.example`.
* Set the "User cannot change password" and "Password never expires" options
  on the account
* Set a strong password on it
* From a Windows `cmd.exe` window, generate the service principals and keytabs
  for this user.  You need an SPN named `host/foo.example.com`, and another
  named `HTTP/foo.example.com`. It is crucial that `foo.example.com` is the
  DNS name of your web site in the intranet, and it is an `A` record.  Given
  that `app.example` is the account name you created, you would execute:

        C:\> ktpass -princ host/foo.example.com@EXAMPLE.COM -mapuser
        EXAMPLECOM\app.example -pass * -out host.keytab -ptype KRB5_NT_PRINCIPAL

        C:\> ktpass -princ HTTP/foo.example.com@EXAMPLE.COM -mapuser
        EXAMPLECOM\app.example -pass * -out http.keytab -ptype KRB5_NT_PRINCIPAL

* Verify that the correct SPNs are created:

        C:\> setspn -Q */foo.example.com

  it should yield both the `HTTP/` and `host/` SPNs, both mapped to the
  `app.example` user.


Crash course to UNIX KRB5 and nginx configuration
-------------------------------------------------

* Verify that your UNIX machine is using the same DNS server as your DC, most
  likely it'll use the DC itself.

* Create an /etc/krb5.conf configuration file, replacing the realm and kdc
  host names with your own AD setup:

        [libdefaults]
          default_tkt_enctypes = arcfour-hmac-md5
          default_tgs_enctypes = arcfour-hmac-md5
          default_keytab_name  = FILE:/etc/krb5.keytab
          default_realm        = EXAMPLE.COM
          ticket_lifetime      = 24h
          kdc_timesync         = 1
          ccache_type          = 4
          forwardable          = false
          proxiable            = false

        [realms]
          EXAMPLE.COM = {
              kdc            = dc.example.com
              admin_server   = dc.example.com
              default_domain = example.com
          }

        [domain_realm]
          .kerberos.server = EXAMPLE.COM
          .example.com     = EXAMPLE.COM

* Copy the two keytab files (`host.keytab` and `http.keytab`) created with
  ktpass on Windows to your UNIX machine.

* Create a krb5.keytab using ktutil, concatenating together the two SPNs keytabs:

        # ktutil
        ktutil:  rkt host.keytab
        ktutil:  rkt http.keytab
        ktutil:  wkt /etc/krb5.keytab
        ktutil:  quit

* Verify that the created keytab file has been built correctly:

        # klist -kt /etc/krb5.keytab
        Keytab name: WRFILE:/etc/krb5.keytab
        KVNO Timestamp         Principal
        ---- ----------------- --------------------------------------------------------
        9 02/19/13 04:02:48 HTTP/foo.example.com@EXAMPLE.COM
        8 02/19/13 04:02:48 host/foo.example.com@EXAMPLE.COM

  Key version numbers (`KVNO`) will be different in your case.


* Verify that you are able to authenticate using the keytab, without password:

        # kinit -5 -V -k -t /etc/krb5.keytab HTTP/foo.example.com
        Authenticated to Kerberos v5

        # klist
        Ticket cache: FILE:/tmp/krb5cc_0
        Default principal: HTTP/foo.example.com@EXAMPLE.COM

        Valid starting     Expires            Service principal
        02/19/13 17:37:42  02/20/13 03:37:40  krbtgt/EXAMPLE.COM@EXAMPLE.COM
                renew until 02/20/13 17:37:42

* Make the keytab file accessible only by root and the nginx group:

        # chmod 440 /etc/krb5.keytab
        # chown root:nginx /etc/krb5.keytab

* Configure a SPNEGO-protected location in the nginx configuration file:

        server {
          server_name foo.example.com;

          ssl on;
          ssl_certificate     example.com.crt;
          ssl_certificate_key example.com.crt;

          location / {
            root /some/where;
            index index.html;
            auth_gss on;
            auth_gss_realm EXAMPLE.COM;
            auth_gss_keytab /etc/krb5.keytab;
            auth_gss_service_name HTTP;
          }
        }

  The SPN will be built as follows:

        $auth_gss_service_name / $server_name @ $auth_gss_realm

  In the above example, it'll be `HTTP/foo.example.com@EXAMPLE.COM`. You can
  specify a fully-qualified SPN in the `auth_gss_service_name` configuration
  option, in this case the `server_name` won't be added automatically.

Help
----

If you're unable to figure things out, please feel free to open an
issue on Github and I'll do my best to help you.
