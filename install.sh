#!/bin/sh

VERSION=0.3.2
BRANCH=main
ARCH=$(arch)

# Detect distribution type
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ -n "$ID" ]; then
            case "$ID" in
                debian|ubuntu|raspbian)
                    echo "deb"
                    return 0
                    ;;
                rhel|centos|fedora|rocky|almalinux|ol)
                    echo "rpm"
                    return 0
                    ;;
            esac
        fi
    fi

    # Fallback: check for package managers
    if command -v dpkg >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
        echo "deb"
        return 0
    fi

    if command -v rpm >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        echo "rpm"
        return 0
    fi

    echo "unknown"
    return 1
}

DISTRO_TYPE=$(detect_distro)

# Install dependencies
echo "Installing dependencies..."
if [ "$DISTRO_TYPE" = "deb" ]; then
    apt-get update -qq
    apt-get install -yqq curl sed clamav-daemon redis-server
elif [ "$DISTRO_TYPE" = "rpm" ]; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl sed clamav redis
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl sed clamav redis
    fi
else
    echo "Warning: Could not detect distribution type. Attempting to install dependencies with apt-get..."
    apt-get update -qq 2>/dev/null || true
    apt-get install -yqq curl sed clamav-daemon redis-server 2>/dev/null || true
fi

# Setup ClamAV
echo "Setting up ClamAV..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/clamd/clamd.conf -o /etc/clamav/clamd.conf
mkdir -p /etc/systemd/system/clamav-daemon.socket.d
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/systemd/clamd/override.conf -o /etc/systemd/system/clamav-daemon.socket.d/override.conf
systemctl daemon-reload
systemctl enable clamav-daemon
systemctl restart clamav-daemon
systemctl status clamav-daemon

echo "ClamAV setup complete."
sleep 1

# Install synapse
echo "Installing synapse ${VERSION} for ${ARCH}..."
INSTALLED=0

if [ "$DISTRO_TYPE" = "deb" ]; then
    echo "Attempting to install .deb package..."
    DEB_URL="https://github.com/gen0sec/synapse/releases/download/v${VERSION}/synapse_${VERSION}_${ARCH}.deb"
    if curl -fSL "${DEB_URL}" -o /tmp/synapse_${VERSION}_${ARCH}.deb 2>/dev/null; then
        if dpkg -i /tmp/synapse_${VERSION}_${ARCH}.deb 2>/dev/null || apt-get install -y -f /tmp/synapse_${VERSION}_${ARCH}.deb 2>/dev/null; then
            echo "Successfully installed synapse from .deb package"
            INSTALLED=1
        fi
    fi
elif [ "$DISTRO_TYPE" = "rpm" ]; then
    echo "Attempting to install .rpm package..."
    RPM_URL="https://github.com/gen0sec/synapse/releases/download/v${VERSION}/synapse-${VERSION}-${ARCH}.rpm"
    if curl -fSL "${RPM_URL}" -o /tmp/synapse-${VERSION}-${ARCH}.rpm 2>/dev/null; then
        if rpm -i /tmp/synapse-${VERSION}-${ARCH}.rpm 2>/dev/null || (command -v dnf >/dev/null 2>&1 && dnf install -y /tmp/synapse-${VERSION}-${ARCH}.rpm 2>/dev/null) || (command -v yum >/dev/null 2>&1 && yum install -y /tmp/synapse-${VERSION}-${ARCH}.rpm 2>/dev/null); then
            echo "Successfully installed synapse from .rpm package"
            INSTALLED=1
        fi
    fi
fi

# Fallback to binary installation
if [ "$INSTALLED" -eq 0 ]; then
    echo "Package installation not available or failed. Falling back to binary installation..."
    curl -fSL https://github.com/gen0sec/synapse/releases/download/v${VERSION}/synapse-${ARCH}-unknown-linux-gnu.tar.gz -o /tmp/synapse-${ARCH}-unknown-linux-gnu.tar.gz
    tar -C /usr/local/bin -xzf /tmp/synapse-${ARCH}-unknown-linux-gnu.tar.gz
    echo "Successfully installed synapse from binary"
fi

# Install service
echo "Installing service..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/others/systemd/synapse.service -o /etc/systemd/system/synapse.service
systemctl daemon-reload

# Create directories
echo "Creating directories..."
mkdir -p /var/log/synapse /var/run/synapse /var/lib/synapse /etc/synapse

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/config_example.yaml -o /etc/synapse/config.yaml
chmod 640 /etc/synapse/config.yaml
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/${BRANCH}/upstreams_example.yaml -o /etc/synapse/upstreams.yaml
chmod 644 /etc/synapse/upstreams.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable synapse

echo "Before starting the service, you need to add your API key to the config file /etc/synapse/config.yaml."
sleep 1
echo "You can get your API key from https://dash.gen0sec.com/settings/api-keys."
sleep 1
echo "Then run 'systemctl start synapse' to start the service."
