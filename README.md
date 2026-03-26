# Android SIGMA Rules

The first open SIGMA-compatible detection rule set for Android mobile security.

## What is this?

SIGMA rules for detecting threats on Android devices — stalkerware, banking trojans, RATs, mercenary spyware, and device misconfiguration. Rules are evaluated on-device by [AndroDR](https://github.com/yasirhamza/AndroDR) or can be converted for SIEM use.

## Rule format

Standard SIGMA YAML with `product: androdr`:

```yaml
title: Sideloaded app with system-impersonating name
id: androdr-016
status: production
logsource:
    product: androdr
    service: app_scanner
detection:
    selection_untrusted:
        is_system_app: false
        from_trusted_store: false
    selection_name:
        app_name|contains:
            - System
            - Google
    condition: selection_untrusted and selection_name
level: high
remediation:
    - "Uninstall unless you specifically installed it."
```

## Services

| Service | What it scans |
|---------|--------------|
| `app_scanner` | Installed app metadata (packages, permissions, certs) |
| `device_auditor` | Device security posture (ADB, bootloader, patch level) |
| `dns_monitor` | DNS queries intercepted by local VPN |

## Field vocabulary

### `service: app_scanner`

| Field | Type | Description |
|-------|------|-------------|
| `package_name` | String | Android package name |
| `app_name` | String | Display name |
| `cert_hash` | String | SHA-256 of signing cert |
| `is_system_app` | Boolean | FLAG_SYSTEM set |
| `from_trusted_store` | Boolean | Play Store / Galaxy Store |
| `installer` | String | Installer package name |
| `is_sideloaded` | Boolean | Untrusted source |
| `permissions` | List | Dangerous permissions |
| `surveillance_permission_count` | Int | Count of surveillance perms |
| `has_accessibility_service` | Boolean | Declares AccessibilityService |
| `has_device_admin` | Boolean | Declares DeviceAdminReceiver |

### `service: device_auditor`

| Field | Type | Description |
|-------|------|-------------|
| `check_id` | String | Check identifier |
| `adb_enabled` | Boolean | USB debugging on |
| `screen_lock_enabled` | Boolean | Lock configured |
| `patch_age_days` | Int | Days since patch |
| `bootloader_unlocked` | Boolean | Bootloader unlocked |

### `service: dns_monitor`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | String | Queried domain |
| `is_blocked` | Boolean | Blocked by IOC list |

## Contributing

1. Fork this repo
2. Add a rule YAML in the appropriate `service/` directory
3. Follow the naming convention: `androdr_NNN_short_description.yml`
4. Tag with MITRE ATT&CK techniques
5. Submit a PR

## License

CC-BY-4.0
