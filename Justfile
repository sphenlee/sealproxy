# show this help
help:
    just --list

# generate a keypair for signing sessions (requires openssl)
gen-keypair:
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# generate a TLS certificate and key (requires mkcert)
gen-tlscert:
    mkcert -key-file localhost.key -cert-file localhost.crt localhost

# luanch the testing LDAP server
start-ldap:
    docker run --rm -p 10389:10389 rroemhild/test-openldap

# do a full release build
build:
    cargo build --release

# build Sealproxy into a docker image for local use
package: build
    docker build . -t sealproxy:local
