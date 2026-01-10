FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y systemd systemd-sysv dbus curl python3 python3-pip sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a user for ansible
RUN useradd -m -s /bin/bash ansible && \
    echo "ansible ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Prevent systemd from exiting
RUN systemctl set-default multi-user.target || true

CMD ["/usr/lib/systemd/systemd", "--system"]
