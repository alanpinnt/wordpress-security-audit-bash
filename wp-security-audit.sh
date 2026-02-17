#!/usr/bin/env bash
#
# wp-security-audit.sh - WordPress security audit scanner
# Checks file permissions, exposed sensitive files, outdated plugins/themes,
# and known vulnerable plugin versions.
#
# Usage: ./wp-security-audit.sh [options]
#   -p, --path DIR       Path to WordPress installation (default: /var/www/html)
#   -o, --output FILE    Write report to file instead of stdout
#   -q, --quiet          Only show warnings and failures
#   -h, --help           Show this help message

set -euo pipefail

# ---------- Defaults ----------

WP_PATH="/var/www/html"
OUTPUT_FILE=""
QUIET=false
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0

# Colors (disabled if not a terminal or writing to file)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' YELLOW='' GREEN='' BLUE='' BOLD='' RESET=''
fi

# ---------- Output Functions ----------

_output() {
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "$*" >> "$OUTPUT_FILE"
    else
        echo -e "$*"
    fi
}

header() {
    _output "\n${BOLD}── $* ──${RESET}"
}

pass() {
    ((PASS_COUNT++))
    [[ "$QUIET" == true ]] && return
    _output "  ${GREEN}[PASS]${RESET} $*"
}

warn() {
    ((WARN_COUNT++))
    _output "  ${YELLOW}[WARN]${RESET} $*"
}

fail() {
    ((FAIL_COUNT++))
    _output "  ${RED}[FAIL]${RESET} $*"
}

info() {
    ((INFO_COUNT++))
    [[ "$QUIET" == true ]] && return
    _output "  ${BLUE}[INFO]${RESET} $*"
}

# ---------- Argument Parsing ----------

usage() {
    sed -n '6,10p' "$0" | sed 's/^# \?//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--path) WP_PATH="$2"; shift 2 ;;
            -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
            -q|--quiet) QUIET=true; shift ;;
            -h|--help) usage ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
}

# ---------- Validation ----------

validate() {
    [[ -d "$WP_PATH" ]] || { echo "WordPress path not found: $WP_PATH" >&2; exit 1; }
    [[ -f "${WP_PATH}/wp-config.php" ]] || { echo "wp-config.php not found in $WP_PATH — is this a WordPress installation?" >&2; exit 1; }

    if [[ -n "$OUTPUT_FILE" ]]; then
        # Disable colors when writing to file
        RED='' YELLOW='' GREEN='' BLUE='' BOLD='' RESET=''
        > "$OUTPUT_FILE"
    fi
}

# ---------- Checks ----------

check_wp_version() {
    header "WordPress Core Version"

    local version_file="${WP_PATH}/wp-includes/version.php"
    if [[ ! -f "$version_file" ]]; then
        warn "Could not determine WordPress version (version.php not found)"
        return
    fi

    local wp_version
    wp_version="$(grep -oP "\\\$wp_version\s*=\s*'\K[^']+" "$version_file" 2>/dev/null || true)"

    if [[ -z "$wp_version" ]]; then
        warn "Could not parse WordPress version"
        return
    fi

    info "Installed version: $wp_version"

    # Check if WP-CLI is available for update check
    if command -v wp &>/dev/null; then
        local latest
        latest="$(wp core check-update --path="$WP_PATH" --format=csv --fields=version 2>/dev/null | tail -1 || true)"
        if [[ -n "$latest" && "$latest" != "version" ]]; then
            fail "WordPress $wp_version is outdated — $latest available"
        else
            pass "WordPress $wp_version appears to be current"
        fi
    else
        info "Install WP-CLI for automatic update checking"
    fi
}

check_file_permissions() {
    header "File Permissions"

    # wp-config.php should not be world-readable
    local wp_config="${WP_PATH}/wp-config.php"
    local perms
    perms="$(stat -c '%a' "$wp_config" 2>/dev/null || true)"

    if [[ -n "$perms" ]]; then
        local other="${perms: -1}"
        if [[ "$other" -ge 4 ]]; then
            fail "wp-config.php is world-readable (${perms}) — recommended: 640 or 600"
        else
            pass "wp-config.php permissions: $perms"
        fi
    fi

    # Check directory permissions (should not be 777)
    local bad_dirs
    bad_dirs="$(find "$WP_PATH" -type d -perm 0777 2>/dev/null | head -20)"
    if [[ -n "$bad_dirs" ]]; then
        local count
        count="$(echo "$bad_dirs" | wc -l)"
        fail "$count directories with 777 permissions found"
        echo "$bad_dirs" | head -5 | while read -r dir; do
            _output "       $dir"
        done
        [[ "$count" -gt 5 ]] && _output "       ... and $((count - 5)) more"
    else
        pass "No directories with 777 permissions"
    fi

    # Check for world-writable files
    local bad_files
    bad_files="$(find "$WP_PATH" -type f -perm -o+w -not -path '*/cache/*' 2>/dev/null | head -20)"
    if [[ -n "$bad_files" ]]; then
        local count
        count="$(echo "$bad_files" | wc -l)"
        warn "$count world-writable files found (excluding cache)"
        echo "$bad_files" | head -5 | while read -r f; do
            _output "       $f"
        done
        [[ "$count" -gt 5 ]] && _output "       ... and $((count - 5)) more"
    else
        pass "No world-writable files found"
    fi
}

check_exposed_files() {
    header "Exposed Sensitive Files"

    local sensitive_paths=(
        ".git"
        ".git/config"
        ".env"
        ".htaccess.bak"
        "wp-config.php.bak"
        "wp-config.php~"
        "wp-config-sample.php"
        "readme.html"
        "license.txt"
        "xmlrpc.php"
        "wp-admin/install.php"
    )

    for path in "${sensitive_paths[@]}"; do
        local full="${WP_PATH}/${path}"
        if [[ -e "$full" ]]; then
            case "$path" in
                .git|.git/config|.env|*.bak|*~)
                    fail "Sensitive file exposed: $path"
                    ;;
                wp-config-sample.php|readme.html|license.txt)
                    warn "Unnecessary file present: $path (reveals version info)"
                    ;;
                xmlrpc.php)
                    warn "xmlrpc.php is present — consider disabling if not needed (brute force/DDoS vector)"
                    ;;
                wp-admin/install.php)
                    info "install.php present (normal, but should be blocked if WP is already installed)"
                    ;;
            esac
        else
            case "$path" in
                .git|.git/config|.env|*.bak|*~)
                    pass "Not found: $path"
                    ;;
            esac
        fi
    done
}

check_directory_listing() {
    header "Directory Listing Protection"

    local dirs_to_check=(
        "wp-content/uploads"
        "wp-content/plugins"
        "wp-content/themes"
        "wp-includes"
    )

    for dir in "${dirs_to_check[@]}"; do
        local full="${WP_PATH}/${dir}"
        local index_file="${full}/index.php"

        if [[ -d "$full" ]]; then
            if [[ -f "$index_file" ]]; then
                pass "$dir has index.php"
            else
                warn "$dir has no index.php — may allow directory listing"
            fi
        fi
    done
}

check_debug_mode() {
    header "Debug Settings"

    local wp_config="${WP_PATH}/wp-config.php"

    # WP_DEBUG
    if grep -qP "define\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)" "$wp_config" 2>/dev/null; then
        fail "WP_DEBUG is enabled — should be disabled in production"
    else
        pass "WP_DEBUG is disabled"
    fi

    # WP_DEBUG_LOG
    if grep -qP "define\(\s*['\"]WP_DEBUG_LOG['\"]\s*,\s*true\s*\)" "$wp_config" 2>/dev/null; then
        warn "WP_DEBUG_LOG is enabled — debug.log may be publicly accessible"
        if [[ -f "${WP_PATH}/wp-content/debug.log" ]]; then
            local log_size
            log_size="$(du -h "${WP_PATH}/wp-content/debug.log" | cut -f1)"
            fail "debug.log exists ($log_size) — may leak sensitive information"
        fi
    else
        pass "WP_DEBUG_LOG is disabled"
    fi

    # WP_DEBUG_DISPLAY
    if grep -qP "define\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*true\s*\)" "$wp_config" 2>/dev/null; then
        fail "WP_DEBUG_DISPLAY is enabled — errors shown to visitors"
    else
        pass "WP_DEBUG_DISPLAY is not explicitly enabled"
    fi

    # DISALLOW_FILE_EDIT
    if grep -qP "define\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)" "$wp_config" 2>/dev/null; then
        pass "DISALLOW_FILE_EDIT is set — theme/plugin editor disabled"
    else
        warn "DISALLOW_FILE_EDIT is not set — consider adding to wp-config.php to disable the built-in file editor"
    fi
}

check_security_keys() {
    header "Security Keys & Salts"

    local wp_config="${WP_PATH}/wp-config.php"
    local keys=(AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT)
    local missing=()
    local default=()

    for key in "${keys[@]}"; do
        local value
        value="$(grep -oP "define\(\s*'${key}'\s*,\s*'\K[^']+" "$wp_config" 2>/dev/null || true)"
        if [[ -z "$value" ]]; then
            missing+=("$key")
        elif [[ "$value" == "put your unique phrase here" ]]; then
            default+=("$key")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "Missing security keys: ${missing[*]}"
    fi

    if [[ ${#default[@]} -gt 0 ]]; then
        fail "Default/placeholder security keys found: ${default[*]}"
        _output "       Generate new keys at: https://api.wordpress.org/secret-key/1.1/salt/"
    fi

    if [[ ${#missing[@]} -eq 0 && ${#default[@]} -eq 0 ]]; then
        pass "All 8 security keys/salts are set"
    fi
}

check_database_prefix() {
    header "Database Table Prefix"

    local wp_config="${WP_PATH}/wp-config.php"
    local prefix
    prefix="$(grep -oP "\\\$table_prefix\s*=\s*'\K[^']+" "$wp_config" 2>/dev/null || true)"

    if [[ "$prefix" == "wp_" ]]; then
        warn "Default table prefix 'wp_' in use — consider changing to reduce automated SQL injection risk"
    elif [[ -n "$prefix" ]]; then
        pass "Custom table prefix in use: '${prefix}'"
    else
        warn "Could not determine table prefix"
    fi
}

check_plugins() {
    header "Plugin Audit"

    local plugin_dir="${WP_PATH}/wp-content/plugins"
    [[ -d "$plugin_dir" ]] || { info "No plugins directory found"; return; }

    local plugin_count=0
    local inactive_indicators=0

    while IFS= read -r -d '' plugin_path; do
        ((plugin_count++))
        local plugin_name
        plugin_name="$(basename "$plugin_path")"

        # Check for readme.txt to get version
        local readme="${plugin_path}/readme.txt"
        local version="unknown"
        if [[ -f "$readme" ]]; then
            version="$(grep -iP "^Stable tag:\s*\K.*" "$readme" 2>/dev/null | tr -d '[:space:]' || echo "unknown")"
        fi

        # Check main plugin file for version as fallback
        if [[ "$version" == "unknown" || "$version" == "trunk" ]]; then
            local main_file
            main_file="$(find "$plugin_path" -maxdepth 1 -name '*.php' -exec grep -l 'Plugin Name:' {} \; 2>/dev/null | head -1)"
            if [[ -n "$main_file" ]]; then
                version="$(grep -ioP "Version:\s*\K[\d.]+" "$main_file" 2>/dev/null || echo "unknown")"
            fi
        fi

        info "Plugin: $plugin_name (v$version)"

    done < <(find "$plugin_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

    info "Total plugins found: $plugin_count"

    if command -v wp &>/dev/null; then
        local outdated
        outdated="$(wp plugin list --path="$WP_PATH" --update=available --format=csv --fields=name,version,update_version 2>/dev/null || true)"
        if [[ -n "$outdated" && "$outdated" != "name,version,update_version" ]]; then
            local update_count
            update_count="$(echo "$outdated" | tail -n +2 | wc -l)"
            warn "$update_count plugin(s) have updates available:"
            echo "$outdated" | tail -n +2 | while IFS=',' read -r name ver new_ver; do
                _output "       $name: $ver -> $new_ver"
            done
        else
            pass "All plugins are up to date"
        fi

        # Check for inactive plugins
        local inactive
        inactive="$(wp plugin list --path="$WP_PATH" --status=inactive --format=csv --fields=name 2>/dev/null || true)"
        if [[ -n "$inactive" && "$inactive" != "name" ]]; then
            local inactive_count
            inactive_count="$(echo "$inactive" | tail -n +2 | wc -l)"
            warn "$inactive_count inactive plugin(s) — consider removing unused plugins"
            echo "$inactive" | tail -n +2 | while read -r name; do
                _output "       $name"
            done
        fi
    else
        info "Install WP-CLI for plugin update and status checks"
    fi
}

check_themes() {
    header "Theme Audit"

    local theme_dir="${WP_PATH}/wp-content/themes"
    [[ -d "$theme_dir" ]] || { info "No themes directory found"; return; }

    local theme_count=0

    while IFS= read -r -d '' theme_path; do
        ((theme_count++))
        local theme_name
        theme_name="$(basename "$theme_path")"

        local style="${theme_path}/style.css"
        local version="unknown"
        if [[ -f "$style" ]]; then
            version="$(grep -ioP "Version:\s*\K[\d.]+" "$style" 2>/dev/null || echo "unknown")"
        fi

        info "Theme: $theme_name (v$version)"
    done < <(find "$theme_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

    info "Total themes found: $theme_count"

    if [[ "$theme_count" -gt 3 ]]; then
        warn "$theme_count themes installed — keep only the active theme and one default fallback"
    fi

    if command -v wp &>/dev/null; then
        local outdated
        outdated="$(wp theme list --path="$WP_PATH" --update=available --format=csv --fields=name,version,update_version 2>/dev/null || true)"
        if [[ -n "$outdated" && "$outdated" != "name,version,update_version" ]]; then
            local update_count
            update_count="$(echo "$outdated" | tail -n +2 | wc -l)"
            warn "$update_count theme(s) have updates available:"
            echo "$outdated" | tail -n +2 | while IFS=',' read -r name ver new_ver; do
                _output "       $name: $ver -> $new_ver"
            done
        else
            pass "All themes are up to date"
        fi
    fi
}

check_php_exposure() {
    header "PHP & Server Exposure"

    # Check for phpinfo files
    local phpinfo_files
    phpinfo_files="$(find "$WP_PATH" -maxdepth 2 -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' -o -name 'pi.php' 2>/dev/null || true)"
    if [[ -n "$phpinfo_files" ]]; then
        fail "Potentially dangerous PHP files found:"
        echo "$phpinfo_files" | while read -r f; do
            _output "       $f"
        done
    else
        pass "No common phpinfo/test files found"
    fi

    # Check for error_log files
    local error_logs
    error_logs="$(find "$WP_PATH" -maxdepth 3 -name 'error_log' -o -name 'php_errorlog' 2>/dev/null | head -5 || true)"
    if [[ -n "$error_logs" ]]; then
        warn "PHP error log files found in web root:"
        echo "$error_logs" | while read -r f; do
            _output "       $f"
        done
    else
        pass "No PHP error logs in web root"
    fi
}

check_ssl_config() {
    header "SSL / HTTPS"

    local wp_config="${WP_PATH}/wp-config.php"

    # FORCE_SSL_ADMIN
    if grep -qP "define\(\s*['\"]FORCE_SSL_ADMIN['\"]\s*,\s*true\s*\)" "$wp_config" 2>/dev/null; then
        pass "FORCE_SSL_ADMIN is enabled"
    else
        warn "FORCE_SSL_ADMIN is not set — admin login should use HTTPS"
    fi

    # Check site URL for https
    local site_url
    site_url="$(grep -oP "define\(\s*'WP_SITEURL'\s*,\s*'\K[^']+" "$wp_config" 2>/dev/null || true)"
    local home_url
    home_url="$(grep -oP "define\(\s*'WP_HOME'\s*,\s*'\K[^']+" "$wp_config" 2>/dev/null || true)"

    if [[ -n "$site_url" ]]; then
        if [[ "$site_url" == https://* ]]; then
            pass "WP_SITEURL uses HTTPS"
        else
            fail "WP_SITEURL uses HTTP: $site_url"
        fi
    fi

    if [[ -n "$home_url" ]]; then
        if [[ "$home_url" == https://* ]]; then
            pass "WP_HOME uses HTTPS"
        else
            fail "WP_HOME uses HTTP: $home_url"
        fi
    fi

    if [[ -z "$site_url" && -z "$home_url" ]]; then
        info "Site URLs are set in the database (not wp-config.php) — check manually"
    fi
}

check_user_enumeration() {
    header "User Enumeration"

    # Check .htaccess for author enumeration blocking
    local htaccess="${WP_PATH}/.htaccess"
    if [[ -f "$htaccess" ]]; then
        if grep -q "author=" "$htaccess" 2>/dev/null; then
            pass "Author enumeration appears to be restricted in .htaccess"
        else
            info "Consider blocking /?author=N enumeration in .htaccess"
        fi
    else
        info "No .htaccess file found"
    fi
}

# ---------- Summary ----------

print_summary() {
    _output "\n${BOLD}── Summary ──${RESET}"
    _output "  ${GREEN}Passed:${RESET}   $PASS_COUNT"
    _output "  ${YELLOW}Warnings:${RESET} $WARN_COUNT"
    _output "  ${RED}Failed:${RESET}   $FAIL_COUNT"
    _output "  ${BLUE}Info:${RESET}     $INFO_COUNT"

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        _output "\n  ${RED}${BOLD}Action required:${RESET} $FAIL_COUNT critical issue(s) found."
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        _output "\n  ${YELLOW}${BOLD}Review recommended:${RESET} $WARN_COUNT warning(s) to address."
    else
        _output "\n  ${GREEN}${BOLD}Looking good!${RESET} No critical issues found."
    fi
    _output ""
}

# ---------- Main ----------

main() {
    parse_args "$@"
    validate

    _output "${BOLD}WordPress Security Audit${RESET}"
    _output "Path: $WP_PATH"
    _output "Date: $(date '+%Y-%m-%d %H:%M:%S')"

    check_wp_version
    check_file_permissions
    check_exposed_files
    check_directory_listing
    check_debug_mode
    check_security_keys
    check_database_prefix
    check_plugins
    check_themes
    check_php_exposure
    check_ssl_config
    check_user_enumeration

    print_summary

    # Exit code based on findings
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        exit 2
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
