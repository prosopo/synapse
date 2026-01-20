# Copyright (C) 2025, Gen0Sec.

%global debug_package %{nil}

Summary:     High-performance reverse proxy and firewall
Name:        synapse
Version:     %{_version}
Release:     1
License:     ELv2
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://github.com/gen0sec/synapse
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Gen0Sec <support@gen0sec.com>
Packager:    Gen0Sec <support@gen0sec.com>
AutoReqProv: no
ExclusiveOS: linux
Requires: openssl
BuildRequires: openssl-devel, perl, gcc, make

%description
Synapse is a high-performance reverse proxy and firewall built with Rust, featuring
XDP-based packet filtering, dynamic access rules, threat intelligence integration,
and advanced routing capabilities. It provides ultra-low latency protection at the
kernel level and can operate in reverse proxy mode or firewall-only mode.

# -----------------------------------------------------------------------------

%prep
%setup -q
if ! command -v cargo &> /dev/null; then
    curl https://sh.rustup.rs -sSf | sh -s -- -y
fi

# -----------------------------------------------------------------------------

%build
source $HOME/.cargo/env
export OPENSSL_DIR=%{_prefix}
export OPENSSL_STATIC=0
export PKG_CONFIG_ALLOW_CROSS=1
cargo build --release

# -----------------------------------------------------------------------------

%install
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_configdir}
mkdir -p -m 750 ${RPM_BUILD_ROOT}%{_configdir}/certs
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p -m 640 ${RPM_BUILD_ROOT}/lib/systemd/system
mkdir -p -m 640 ${RPM_BUILD_ROOT}/usr/share/man/man1
mkdir -p -m 755 ${RPM_BUILD_ROOT}/var/log/synapse
mkdir -p -m 755 ${RPM_BUILD_ROOT}/var/lib/synapse

install -m 0750 target/release/synapse ${RPM_BUILD_ROOT}%{_bindir}/
install -m 0640 config/config.yaml ${RPM_BUILD_ROOT}%{_configdir}/
install -m 0644 pkg/synapse.service ${RPM_BUILD_ROOT}/lib/systemd/system/
install -m 0644 pkg/synapse.1 ${RPM_BUILD_ROOT}/usr/share/man/man1/
gzip -9 ${RPM_BUILD_ROOT}/usr/share/man/man1/synapse.1

# -----------------------------------------------------------------------------

%pre

# -----------------------------------------------------------------------------

%post
# Create certs directory if it doesn't exist
mkdir -p /etc/synapse/certs
chmod 750 /etc/synapse/certs

# Generate default certificate if it doesn't exist
if [ ! -f /etc/synapse/certs/default.crt ] || [ ! -f /etc/synapse/certs/default.key ]; then
    echo "Generating default SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/synapse/certs/default.key \
        -out /etc/synapse/certs/default.crt \
        -subj "/C=US/ST=State/L=City/O=Synapse/CN=localhost" \
        2>/dev/null

    # Set appropriate permissions
    chmod 600 /etc/synapse/certs/default.key
    chmod 644 /etc/synapse/certs/default.crt
    chown root:root /etc/synapse/certs/default.key /etc/synapse/certs/default.crt

    echo "Default SSL certificate generated at /etc/synapse/certs/default.crt"
fi

# Create log directory if it doesn't exist
mkdir -p /var/log/synapse
chown root:root /var/log/synapse

# Create working directory for the service
mkdir -p /var/lib/synapse
chown root:root /var/lib/synapse

# Reload systemd daemon to recognize the new service file
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# -----------------------------------------------------------------------------

%preun
if [ $1 = 0 ];then
    echo -n "Stopping Synapse service..."
    if command -v systemctl > /dev/null 2>&1 && systemctl is-active --quiet %{name} > /dev/null 2>&1; then
        systemctl --no-reload stop %{name}.service > /dev/null 2>&1
        systemctl disable %{name} > /dev/null 2>&1
        systemctl daemon-reload > /dev/null 2>&1
    fi
    echo " OK"
fi

# -----------------------------------------------------------------------------

%postun

# -----------------------------------------------------------------------------

%posttrans
if systemctl is-active --quiet %{name} > /dev/null 2>&1; then
    echo -n "Restarting Synapse process to reload configuration..."
    if command -v systemctl > /dev/null 2>&1; then
        systemctl daemon-reload > /dev/null 2>&1
        systemctl restart %{name}.service > /dev/null 2>&1
    fi
    echo " OK"
fi

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%defattr(-,root,root)
%attr(750, root, root) %{_bindir}/synapse
%dir %attr(750, root, root) %{_configdir}
%dir %attr(750, root, root) %{_configdir}/certs
%attr(640, root, root) %config(noreplace) %{_configdir}/config.yaml
%attr(644, root, root) /lib/systemd/system/synapse.service
%attr(644, root, root) /usr/share/man/man1/synapse.1.gz
%dir %attr(755, root, root) /var/log/synapse
%dir %attr(755, root, root) /var/lib/synapse

# -----------------------------------------------------------------------------

%changelog

* Tue Jan 20 2026 Gen0Sec <support@gen0sec.com> - 0.3.3-1
- Release synapse 0.3.3
- More info: https://github.com/gen0sec/synapse/releases

* Tue Jan 20 2026 Gen0Sec <support@gen0sec.com> - 0.3.3-1
- Release synapse 0.3.3
- More info: https://github.com/gen0sec/synapse/releases

* Tue Jan 20 2026 Gen0Sec <support@gen0sec.com> - 0.3.3-1
- Release synapse 0.3.3
- More info: https://github.com/gen0sec/synapse/releases

* Fri Jan 09 2026 Gen0Sec <support@gen0sec.com> - 0.3.2-1
- Release synapse 0.3.2
- More info: https://github.com/gen0sec/synapse/releases

* Fri Jan 09 2026 Gen0Sec <support@gen0sec.com> - 0.3.1-1
- Release synapse 0.3.1
- More info: https://github.com/gen0sec/synapse/releases
* Wed Jan 01 2025 Gen0Sec <support@gen0sec.com> - 0.2.4
- Initial Synapse RPM package
- More info: https://github.com/gen0sec/synapse/releases
