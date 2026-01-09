# Synapse Installation Ansible Playbook

This Ansible playbook automates the installation and configuration of synapse, replicating the functionality of `install.sh`.

## Structure

The playbook is modularized into roles:
- **`roles/synapse/`** - Handles synapse installation and configuration
- **`roles/fail2ban/`** - Optional Fail2Ban integration with Gen0Sec API

Each role can be used independently or together via the main playbook.

## Requirements

- Ansible 2.9 or later
- SSH access to target hosts with sudo privileges

## Quick Start

1. **Set up inventory file:**
   ```bash
   cp hosts.example hosts
   # Edit hosts and add your server details
   ```

2. **Configure variables:**
   ```bash
   mkdir -p group_vars
   cp group_vars/all.example.yml group_vars/all.yml
   # Edit group_vars/all.yml and set your API key
   ```

3. **Run the playbook:**
   ```bash
   ansible-playbook playbook.yml
   ```

   Or pass the API key directly:
   ```bash
   ansible-playbook playbook.yml -e synapse_api_key=your_key_here
   ```

## Playbook Features

- Installs dependencies (curl, sed)
- Optionally installs and configures ClamAV with systemd overrides
- Optionally installs Redis
- Installs synapse using .deb/.rpm packages with binary fallback
- Sets up systemd service and directories
- Downloads and configures config.yaml and upstreams.yaml (binary installation only)
- Supports both Debian/Ubuntu and RedHat/CentOS/Fedora systems
- Enables the synapse service (does not start automatically)
- **Optional Fail2Ban integration** with Gen0Sec API

## Variables

### Synapse Variables

- `synapse_version`: Version of synapse to install (default: `0.3.2`)
- `synapse_branch`: GitHub branch for configuration files (default: `main`)
- `synapse_api_key`: API key to set in config.yaml (optional, can be set later)
- `clamav_enabled`: Enable ClamAV installation and configuration (default: `true`)
- `redis_enabled`: Enable Redis installation (default: `true`)

### Fail2Ban Integration Variables (Optional)

- `fail2ban_enabled`: Enable Fail2Ban integration (default: `false`)
- `gen0sec_api_token`: Fail2Ban API token (defaults to `synapse_api_key` if not set)
- `gen0sec_expiration`: Block expiration time in seconds (default: `600` = 10 minutes)
- `fail2ban_jail_enabled`: Enable fail2ban jails (default: `true`)
- `fail2ban_backend`: Fail2Ban backend (default: `systemd`)

### Enabling Fail2Ban Integration

To enable Fail2Ban integration, set `fail2ban_enabled: true` in your `group_vars/all.yml` or pass it via command line:

```bash
ansible-playbook playbook.yml -e fail2ban_enabled=true
```

The Fail2Ban integration will:
- Install fail2ban and jq
- Download and configure the Gen0Sec action file
- Configure jail.local with Gen0Sec integration
- Enable and start the fail2ban service

## Installation Methods

The playbook automatically:
1. Detects the target system's package manager (apt, dnf, or yum)
2. Attempts to install using `.deb` package (Debian/Ubuntu) or `.rpm` package (RHEL/CentOS/Fedora)
3. Falls back to binary installation if packages are not available

## Post-Installation

After running the playbook:
1. Verify the API key is set in `/etc/synapse/config.yaml`
2. Start the service: `systemctl start synapse`
3. Check status: `systemctl status synapse`

You can get your API key from https://dash.gen0sec.com/settings/api-keys
