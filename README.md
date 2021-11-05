Seal Proxy
==========

Seal Proxy is an authenticating proxy intended to be deployed as a sidecar.
It sits in front of your application and ensure requests are autheticated 
according to your configuration.

Features
--------

Seal proxy currently provides:

 * Cookie based sessions using a JWT
 * HTTP Basic logins
 * A form based login

Planned features:

 * Authenticate users via LDAP
 * OAuth2/OpenID Connect based logins
 * SAML Single Sign-on logins

Usage
-----

See `config.yml` for a sample configuration.

Before using Seal Proxy you will need to create some cryptographic keys and 
certificates. Generate these using the commands in the `Justfile`:

    just gen-keypair gen-tlscert
