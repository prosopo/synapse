# Fail2Ban Role

This role configures Fail2Ban with Gen0Sec API integration.

## Role Variables

- `fail2ban_enabled`: Enable Fail2Ban integration (default: `false`)
- `gen0sec_api_key`: Gen0Sec API key (used for both synapse and fail2ban)
- `gen0sec_expiration`: Block expiration time in seconds (default: `600`)
- `fail2ban_jail_enabled`: Enable fail2ban jails (default: `true`)
- `fail2ban_backend`: Fail2Ban backend (default: `systemd`)

## What This Role Does

1. Installs fail2ban and jq
2. Downloads and configures the Gen0Sec action file
3. Configures jail.local with Gen0Sec integration
4. Enables and starts the fail2ban service

## Usage

Include in a playbook:

```yaml
- hosts: all
  roles:
    - role: fail2ban
      vars:
        fail2ban_enabled: true
        gen0sec_api_key: "your_key"
```

Or conditionally:

```yaml
- hosts: all
  roles:
    - role: fail2ban
      when: fail2ban_enabled | bool
```
