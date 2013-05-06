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

Provenance
----------

The initial codebase was a fork of Apache's [`mod_auth_gss_krb5
0.0.5`](http://modgssapache.sf.net) ported to nginx.
