Nginx module to use SPNEGO+GSSAPI+Kerberos for HTTP authentication
==================================================================

This module implements Kerberos authentication through GSSAPI for nginx.
It currently DOES NOT support NTLMSSP.

Pre-requirements
----------------

Please note that Kerberos Authentication over a GSS-enabled HTTP virtual host
works ***only*** if the following conditions are met:

* The client machine is joined to a Windows 2003 or greater domain
* The user is logged on to the domain
* The GSS-enabled virtual host is HTTPS
* The GSS-enabled virtual host name falls under the *Intranet* or *Trusted
  sites* IE security zone
* The GSS-enabled virtual host name exists in the DNS as an `A` record
* You have created the correct Service Principal Names (SPNs) in Active
  Directory, mapped to a service account

Authentication has been tested with (at least) the following:

* Nginx 1.2.6
* Internet Explorer 8.0.7600.16385
* Firefox 10.0.6
* Chrome 20.0.1132.57
* Curl 7.19.5 (GSS-Negotiate), 7.27.0 (SPNEGO/fbopenssl)

The underlying kerberos library used for these tests was MIT KRB5 v1.8.

Installation
------------

Download [nginx source](http://www.nginx.org/en/download.html) and this module
[zipball](https://github.com/ifad/spnego-http-auth-nginx-module/archive/master.zip).

Follow the
[nginx install documentation](http://nginx.org/en/docs/install.html), extract
this module zipball and pass an `--add-module` option to nginx' configure:

    ./configure --add-module=spnego-http-auth-nginx-module-master

We've also made available a pre-built [nginx-spnego package for
OpenSuSE](https://build.opensuse.org/package/show?package=nginx-spnego&project=home%3Avjt%3Aifad).

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

Debugging
---------

The module prints all sort of debugging information if nginx is compiled with
the `--with-debug` option, and the `error_log` directive has a `debug` level.

Look for the `my_gss_name` in the log to ensure it is correct, and look for
the output of the `gss_acquire_cred` return value first. If it passes, then
your keytabs configuration is correct.

Then, look for the `gss_accept_sec_context` log: if the "input token" is
`NTLMSSP` means that the browser has sent an NTLM hash, that is not currently
supported by this module.

A great improvement would be to port over the `mod_auth_ntlm_winbind` using
Samba's `auth_ntlm` helper over to nginx. If you can do that, please do :-).
We'll work on it in the future anyway.


Configuration reference
-----------------------

You can configure GSS authentication on a per-location basis:

* `auth_gss`: on/off, for ease of unsecuring while leaving other options in
  the config file
* `auth_gss_realm`: Kerberos realm name
* `auth_gss_keytab`: absolute path-name to keytab file containing service
  credentials
* `auth_gss_service_name`: service principal name to use when acquiring
  credentials.

These directives are for now they location specific - there is currently no
way to specify main or per server defaults, improvements are more than
welcome.

TODO
----

* Add support for NTLMSSP
* Fix memory leaks
* Security auditing
* More useful logging


History
-------

Michael Shadle paid YoctoPetaBorg from RentACoder to develop this extension as
`ngx_http_auth_sso_module`.  Michael then renamed it to
`ngx_http_auth_spnego_module`. This initial module provided spnego support
using Microsoft's sample spnegohelp files.  Since then, SPNEGO support has
made its way into various GSS/Kerberos libraries.

Various other people have contributed minor patches to make the extension work
in their environments.

Eventually, [`@vjt`](https://github.com/vjt) spent a night to make this work
for [IFAD](http://www.ifad.org), and then wrote this comprehensive README. :-)

Provenance
----------

The initial codebase was a fork of Apache's [`mod_auth_gss_krb5
0.0.5`](http://modgssapache.sf.net) ported to nginx.
