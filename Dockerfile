FROM ubuntu:latest

RUN apt-get update && apt-get install -y dumb-init
RUN apt-get install -y openssl

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/bin/sealproxy"]

WORKDIR /root

COPY target/release/sealproxy /usr/bin/

