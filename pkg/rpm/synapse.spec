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
cargo build --release

# -----------------------------------------------------------------------------

%install
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_configdir}
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p -m 640 ${RPM_BUILD_ROOT}/lib/systemd/system
mkdir -p -m 640 ${RPM_BUILD_ROOT}/usr/share/man/man1

install -m 0750 target/release/synapse ${RPM_BUILD_ROOT}%{_bindir}/
install -m 0640 config/config.yaml ${RPM_BUILD_ROOT}%{_configdir}/
install -m 0644 pkg/synapse.service ${RPM_BUILD_ROOT}/lib/systemd/system/
install -m 0644 pkg/synapse.1 ${RPM_BUILD_ROOT}/usr/share/man/man1/
gzip -9 ${RPM_BUILD_ROOT}/usr/share/man/man1/synapse.1

# -----------------------------------------------------------------------------

%pre

# -----------------------------------------------------------------------------

%post

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
%attr(640, root, root) %config(noreplace) %{_configdir}/config.yaml
%attr(644, root, root) /lib/systemd/system/synapse.service
%attr(644, root, root) /usr/share/man/man1/synapse.1.gz

# -----------------------------------------------------------------------------

%changelog
* Wed Jan 01 2025 Gen0Sec <support@gen0sec.com> - 0.2.4
- Initial Synapse RPM package
- More info: https://github.com/gen0sec/synapse/releases
