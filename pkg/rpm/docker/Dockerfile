FROM redhat/ubi10:10.1-1766033862

RUN yum update -y && \
    yum install -y rpm-build tar gcc git

ADD entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
