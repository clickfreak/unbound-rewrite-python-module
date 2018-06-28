FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install unbound python-unbound -y && \
    chown -R unbound:unbound /etc/unbound/

USER unbound
RUN unbound-anchor -a /var/lib/unbound/root.key -v; true
RUN unbound-control-setup

ENTRYPOINT /usr/sbin/unbound -c /etc/unbound/unbound.conf -d
