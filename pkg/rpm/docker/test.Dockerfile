FROM oraclelinux:9

RUN dnf install -y systemd systemd-libs python3 python3-pip sudo && \
    dnf clean all

# Create a user for ansible
RUN useradd -m -s /bin/bash ansible && \
    echo "ansible ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Prevent systemd from exiting
RUN systemctl set-default multi-user.target || true

CMD ["/usr/lib/systemd/systemd", "--system"]
