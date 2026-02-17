# wordpress-security-audit-bash

A bash script that scans a WordPress installation for common security issues. Checks file permissions, exposed sensitive files, debug settings, plugin/theme status, SSL configuration, and more.

## What It Checks

| Category | Details |
|---|---|
| **Core Version** | Detects installed WordPress version, checks for available updates (via WP-CLI) |
| **File Permissions** | Flags world-readable `wp-config.php`, 777 directories, world-writable files |
| **Exposed Files** | Detects `.git`, `.env`, backup files, `readme.html`, `xmlrpc.php` |
| **Directory Listing** | Checks for `index.php` in `uploads`, `plugins`, `themes`, `wp-includes` |
| **Debug Settings** | `WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT` |
| **Security Keys** | Verifies all 8 salts/keys are set and not using placeholder values |
| **Database Prefix** | Warns if using the default `wp_` table prefix |
| **Plugins** | Lists installed plugins with versions, checks for updates and inactive plugins |
| **Themes** | Lists installed themes, flags excess themes, checks for updates |
| **PHP Exposure** | Finds `phpinfo.php`, `test.php`, error logs in the web root |
| **SSL / HTTPS** | Checks `FORCE_SSL_ADMIN`, `WP_SITEURL`, and `WP_HOME` for HTTPS |
| **User Enumeration** | Checks `.htaccess` for author enumeration blocking |

## Requirements

- `bash` 4.0+
- Read access to the WordPress installation directory
- Optional: [WP-CLI](https://wp-cli.org/) for update checks and plugin/theme status

## Quick Start

```bash
git clone https://github.com/alanpinnt/wordpress-security-audit-bash.git
cd wordpress-security-audit-bash
chmod +x wp-security-audit.sh
./wp-security-audit.sh --path /var/www/html
```

## Usage

```bash
# Scan the default path (/var/www/html)
./wp-security-audit.sh

# Scan a specific WordPress installation
./wp-security-audit.sh --path /var/www/mysite

# Save report to a file
./wp-security-audit.sh --path /var/www/mysite --output report.txt

# Only show warnings and failures
./wp-security-audit.sh --quiet
```

### Options

| Flag | Description |
|---|---|
| `-p, --path DIR` | Path to WordPress installation (default: `/var/www/html`) |
| `-o, --output FILE` | Write report to file instead of stdout |
| `-q, --quiet` | Only show warnings and failures |
| `-h, --help` | Show help message |

## Example Output

```
WordPress Security Audit
Path: /var/www/html
Date: 2026-02-16 14:30:00

── WordPress Core Version ──
  [INFO] Installed version: 6.7.1
  [PASS] WordPress 6.7.1 appears to be current

── File Permissions ──
  [PASS] wp-config.php permissions: 640
  [PASS] No directories with 777 permissions
  [PASS] No world-writable files found

── Debug Settings ──
  [PASS] WP_DEBUG is disabled
  [PASS] WP_DEBUG_LOG is disabled
  [FAIL] WP_DEBUG_DISPLAY is enabled — errors shown to visitors
  [WARN] DISALLOW_FILE_EDIT is not set

── Summary ──
  Passed:   12
  Warnings: 3
  Failed:   1
  Info:     5

  Action required: 1 critical issue(s) found.
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No issues found |
| `1` | Warnings only |
| `2` | One or more critical failures |

## Automating with Cron

Run a weekly audit and email the report:

```cron
0 9 * * 1 /path/to/wp-security-audit.sh -p /var/www/html -o /tmp/wp-audit.txt && mail -s "WP Security Audit" admin@example.com < /tmp/wp-audit.txt
```

## License

[MIT](LICENSE)
