# AndroDR Logsource Taxonomy

All AndroDR rules must declare a `logsource` block with `product: androdr` and one of the
`service` values listed below. The service identifies which scanner or monitor produced
the event record that the rule evaluates against.

```yaml
logsource:
    product: androdr
    service: <service-name>
```

---

## app_scanner

Emitted by the App Scanner component when an installed package is analysed.
One event is produced per installed app per scan run.

| Field | Type | Description |
|---|---|---|
| `package_name` | string | Android package identifier (e.g. `com.example.app`) |
| `app_name` | string | Human-readable application label |
| `cert_hash` | string | SHA-256 fingerprint of the APK signing certificate, prefixed `sha256:` |
| `is_system_app` | boolean | `true` if the app is installed in the system partition |
| `from_trusted_store` | boolean | `true` if the installer was a known trusted app store (Play Store, Galaxy Store, etc.) |
| `is_known_oem_app` | boolean | `true` if the package is in the bundled OEM allowlist |
| `has_accessibility_service` | boolean | `true` if the app declares an `AccessibilityService` component |
| `has_device_admin` | boolean | `true` if the app holds Device Administration privileges |
| `surveillance_permission_count` | integer | Count of high-risk surveillance-capable permissions granted to the app |
| `permissions` | array of strings | Full list of permissions declared by the app manifest |

---

## device_auditor

Emitted by the Device Auditor component once per scan run, reflecting current
device security posture settings.

| Field | Type | Description |
|---|---|---|
| `adb_enabled` | boolean | `true` if USB Debugging (ADB) is currently active |
| `dev_options_enabled` | boolean | `true` if Developer Options are enabled |
| `unknown_sources_enabled` | boolean | `true` if installation from unknown sources is permitted |
| `screen_lock_enabled` | boolean | `true` if a PIN, password, pattern, or biometric lock is configured |
| `patch_level` | string | Security patch date string in `YYYY-MM-DD` format |
| `patch_age_days` | integer | Number of days since the current security patch was released |
| `bootloader_unlocked` | boolean | `true` if the device bootloader is in an unlocked state |
| `wifi_adb_enabled` | boolean | `true` if Wireless ADB (ADB over Wi-Fi / TCP) is active |
| `unpatched_cve_id` | string | A single CVE identifier known to be unpatched on this device (used in single-CVE rules) |
| `unpatched_cves` | array of strings | Full list of CVE identifiers unpatched on this device |

---

## dns_monitor

Emitted by the Local VPN Service DNS monitor for each DNS query captured from
any app running on the device.

| Field | Type | Description |
|---|---|---|
| `domain` | string | The domain name being resolved (e.g. `api.example.com`) |
| `source_package` | string | Package name of the app that issued the DNS query |
| `query_type` | string | DNS record type requested: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, etc. |

---

## process_monitor

Emitted by the Process Monitor for each running process detected on the device.
Requires elevated privileges or a rooted device for full process visibility.

| Field | Type | Description |
|---|---|---|
| `process_name` | string | Name of the running process (maps to `/proc/<pid>/comm`) |
| `package_name` | string | Android package identifier associated with the process, if resolvable |
| `uid` | integer | Unix UID under which the process is running |

---

## file_scanner

Emitted by the File Scanner for each file inspected during a scan pass.

| Field | Type | Description |
|---|---|---|
| `file_path` | string | Absolute path to the file on the device filesystem |
| `file_hash` | string | SHA-256 hash of the file contents, prefixed `sha256:` |
| `file_size` | integer | File size in bytes |
