FROM centos:7

RUN yum install strace unbound unbound-libs unbound-python python-libs -y && \
    yum clean all && \
    rm -rf /var/cache/yum

USER root:unbound
RUN /usr/sbin/unbound-control-setup -d /etc/unbound/

USER unbound
RUN /usr/sbin/unbound-anchor -a /var/lib/unbound/root.key -c /etc/unbound/icannbundle.pem; true

USER root
ENTRYPOINT /usr/sbin/unbound -c /etc/unbound/unbound.conf -d