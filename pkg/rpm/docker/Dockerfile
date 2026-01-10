FROM oraclelinux:9

RUN dnf update -y && \
    dnf install -y rpm-build tar gcc openssl-devel curl git cmake clang llvm \
    elfutils-libelf-devel libzstd-devel perl perl-IPC-Cmd pkg-config make && \
    dnf clean all

# Install Rust toolchain
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

ADD entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
