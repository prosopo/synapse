FROM fedora:latest

RUN dnf update -y && \
    dnf install -y rpm-build tar gcc openssl-devel curl git && \
    dnf clean all

ADD entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
