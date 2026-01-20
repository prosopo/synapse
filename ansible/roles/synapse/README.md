# Synapse Role

This role installs and configures synapse.

## Role Variables

- `synapse_version`: Version of synapse to install (default: `0.3.3`)
- `synapse_branch`: GitHub branch for configuration files (default: `main`)
- `gen0sec_api_key`: Gen0Sec API key to set in config.yaml (optional)
- `clamav_enabled`: Enable ClamAV installation and configuration (default: `true`)
- `redis_enabled`: Enable Redis installation (default: `true`)

## What This Role Does

1. Installs dependencies (curl, sed)
2. Optionally installs and configures ClamAV with systemd overrides (if `clamav_enabled: true`)
3. Optionally installs Redis (if `redis_enabled: true`)
4. Installs synapse using .deb/.rpm packages with binary fallback
5. Sets up systemd service and directories
6. Downloads and configures config.yaml and upstreams.yaml (binary installation only)
7. Enables the synapse service

## Usage

Include in a playbook:

```yaml
- hosts: all
  roles:
    - synapse
```

Or with variables:

```yaml
- hosts: all
  roles:
    - role: synapse
      vars:
        synapse_version: "0.3.3"
        gen0sec_api_key: "your_key"
```
