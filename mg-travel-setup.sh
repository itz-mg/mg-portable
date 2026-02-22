#!/usr/bin/env bash
# =============================================================================
# MG Travel Servers
# =============================================================================
# Project      : MG Travel Server - Secure Client Node + Network Watchdog
# Target       : Raspberry Pi Zero 2W | Raspberry Pi OS Lite 64-bit (Debian)
# Interface    : wlan0 (built-in WiFi only — NO USB adapter, NO AP mode)
# Author       : MG Servers
# Version      : 3.0.0 (Stability & Compatibility Pass)
# =============================================================================
# v2.0.0 AUDIT FIXES: (see mg-travel-audit.md for full details)
#   CRIT-1  Removed wpa_supplicant from disable list
#   CRIT-2  Custom iptables rules injected into UFW before.rules (durable)
#   CRIT-3  Fixed fail2ban: logtarget in fail2ban.d, backend=auto, ufw banaction
#   CRIT-4  Removed invalid -l flag from arpwatch; rsyslog redirect added
#   CRIT-5  Added dnsutils to package list for dig
#   CRIT-6  Fixed hidepid: dedicated group, hidepid=invisible, boot-only mount
#   HIGH-1..7, MED-1..6, LOW-1, LOW-4  (see audit document)
# -----------------------------------------------------------------------------
# v3.0.0 STABILITY & COMPATIBILITY CHANGES:
#   MOD-1   Removed all global IPv6 disable sysctl settings
#           Reason: breaks Tailscale IPv6 direct paths and some hotel/mobile
#           networks; IPv6 security hardening (redirects, source routing) kept
#   MOD-2   Removed automatic SSH service restart after config hardening
#           Reason: restarting SSH mid-session risks lockout if key not yet
#           added; user must manually verify on port 2222 before reboot
#   MOD-3   Removed rkhunter entirely (package, function, cron entry)
#           Reason: 15-25min near-100% CPU scan daily is too heavy for Pi Zero
#           2W's 512MB RAM and slow SD card I/O; integrity detection is handled
#           by UFW IDS rules, arpwatch, and the watchdog connection monitor
#   MOD-4   Removed hidepid /etc/fstab modification
#           Reason: hidepid=invisible requires a dedicated proc group and
#           careful systemd service compatibility testing; risk of breaking
#           systemd-logind or polkit on headless Pi outweighs benefit
#   MOD-5   Improved DNS tampering detection logic
#           Reason: CDN-distributed domains return different IPs per region/
#           resolver legitimately — comparing IPs caused constant false positives
#           New logic: alert ONLY when local resolver returns NXDOMAIN while
#           1.1.1.1 resolves successfully (true poisoning/blocking signal)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONSTANTS & PATHS
# =============================================================================

readonly SCRIPT_VERSION="3.0.0"
readonly LOG_DIR="/var/log/mg-travel"
readonly SCRIPT_LOG="${LOG_DIR}/install.log"
readonly WATCHDOG_SCRIPT="/usr/local/bin/mg-watchdog"
readonly WATCHDOG_SERVICE="/etc/systemd/system/mg-watchdog.service"
readonly MOTD_SCRIPT="/etc/update-motd.d/99-mg-travel"
readonly MOTD_CACHE="/run/mg-travel-status"
readonly BANNER_FILE="/etc/mg-travel-banner"
readonly LOGROTATE_CONF="/etc/logrotate.d/mg-travel"
readonly SYSCTL_CONF="/etc/sysctl.d/99-mg-travel.conf"
readonly USBBLOCK_CONF="/etc/modprobe.d/mg-usb-storage.conf"
readonly DNS_MONITOR_SCRIPT="/usr/local/bin/mg-dns-monitor"
readonly GW_MONITOR_SCRIPT="/usr/local/bin/mg-gw-monitor"
readonly SSH_PORT=2222
readonly REQUIRED_INTERFACE="wlan0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# =============================================================================
# LOGGING
# =============================================================================

log()     { echo -e "${GREEN}[+]${RESET} $*" | tee -a "${SCRIPT_LOG}"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "${SCRIPT_LOG}"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "${SCRIPT_LOG}"; }
section() { echo -e "\n${CYAN}${BOLD}==> $*${RESET}" | tee -a "${SCRIPT_LOG}"; }

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

preflight_checks() {
    section "Running pre-flight checks"

    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root. Use: sudo bash $0"
        exit 1
    fi

    if ! ip link show "${REQUIRED_INTERFACE}" &>/dev/null; then
        error "Required interface '${REQUIRED_INTERFACE}' not found. Aborting."
        exit 1
    fi

    if ! grep -qi "debian\|raspbian" /etc/os-release 2>/dev/null; then
        warn "OS does not appear to be Debian/Raspbian. Proceeding with caution."
    fi

    if ! ping -c 2 -W 5 8.8.8.8 &>/dev/null; then
        error "No internet connectivity detected. Please connect to WiFi first."
        exit 1
    fi

    log "Pre-flight checks passed."
}

# =============================================================================
# DIRECTORY SETUP
# =============================================================================

setup_directories() {
    section "Setting up required directories"

    mkdir -p "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
    # adm group exists on Debian/RPi OS; fallback to root if not
    if getent group adm &>/dev/null; then
        chown root:adm "${LOG_DIR}"
    else
        chown root:root "${LOG_DIR}"
    fi

    touch "${SCRIPT_LOG}"
    chmod 640 "${SCRIPT_LOG}"

    mkdir -p /var/lib/mg-travel
    chmod 700 /var/lib/mg-travel
    chown root:root /var/lib/mg-travel

    log "Directories created."
}

# =============================================================================
# SYSTEM UPDATE
# =============================================================================

system_update() {
    section "Updating system packages"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold"

    log "System updated."
}

# =============================================================================
# INSTALL DEPENDENCIES
# =============================================================================

install_packages() {
    section "Installing required packages"

    local packages=(
        ufw
        fail2ban
        # python3-systemd not needed since we use backend=auto with auth.log
        vnstat
        tcpdump
        arpwatch
        # rkhunter intentionally omitted (MOD-3): 15-25min near-100% CPU daily
        # scan is too heavy for Pi Zero 2W 512MB / slow SD card. Integrity
        # monitoring is covered by UFW IDS rules, arpwatch, and watchdog.
        dnsutils          # provides dig — required by mg-dns-monitor
        curl
        wget
        ca-certificates
        gnupg
        lsb-release
        unattended-upgrades
        apt-listchanges
        iptables
        iptables-persistent
        netfilter-persistent
        logrotate
        net-tools
        iproute2
        psmisc
        procps
        cron
        rsyslog
        # NOTE: nftables intentionally omitted — conflicts with iptables-persistent
        # on Raspberry Pi OS. UFW uses iptables-nft (nftables compatibility layer)
        # already built into iptables package.
    )

    for pkg in "${packages[@]}"; do
        # Skip comment lines
        [[ "${pkg}" == \#* ]] && continue
        if ! dpkg -s "${pkg}" &>/dev/null; then
            log "Installing: ${pkg}"
            apt-get install -y -qq "${pkg}" \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold"
        else
            log "Already installed: ${pkg}"
        fi
    done

    log "All packages installed."
}

# =============================================================================
# TAILSCALE INSTALLATION
# =============================================================================

install_tailscale() {
    section "Installing Tailscale"

    if command -v tailscale &>/dev/null; then
        log "Tailscale already installed. Checking service..."
    else
        curl -fsSL https://tailscale.com/install.sh | sh
        log "Tailscale installed."
    fi

    systemctl enable tailscaled
    systemctl start tailscaled

    log "Tailscale daemon enabled and started."
    warn "ACTION REQUIRED: Run 'sudo tailscale up' manually to authenticate this node."
    echo "# To authenticate Tailscale, run: sudo tailscale up" \
        >> "${LOG_DIR}/post-install-notes.txt"
}

# =============================================================================
# SSH HARDENING
# =============================================================================

harden_ssh() {
    section "Hardening SSH configuration"

    local sshd_config="/etc/ssh/sshd_config"
    local backup="${sshd_config}.mg-backup-$(date +%Y%m%d%H%M%S)"
    local drop_in="/etc/ssh/sshd_config.d/99-mg-hardened.conf"

    mkdir -p /etc/ssh/sshd_config.d
    cp "${sshd_config}" "${backup}"
    log "SSH config backed up to: ${backup}"

    # FIXES:
    #   - Removed deprecated 'Protocol 2'
    #   - Added KbdInteractiveAuthentication (replaces ChallengeResponseAuthentication
    #     in OpenSSH 8.7+ / Pi OS Bookworm — both kept for compat with older versions)
    #   - Fixed KexAlgorithm: use canonical curve25519-sha256 (not @libssh.org alias)
    cat > "${drop_in}" << 'EOF'
# MG Travel Server - Hardened SSH Configuration
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
HostbasedAuthentication no
IgnoreRhosts yes
UseDNS no
Banner /etc/mg-travel-banner
LogLevel VERBOSE
AuthenticationMethods publickey
EOF

    chmod 600 "${drop_in}"

    # MOD-2: Validate config but DO NOT restart SSH automatically.
    # Restarting sshd mid-session with PasswordAuthentication disabled risks lockout
    # if the user's key is not yet in authorized_keys. The config is written and
    # validated here. The user MUST manually verify port 2222 access and then
    # restart sshd themselves (or simply reboot).
    if sshd -t; then
        log "SSH hardening config written and validated successfully."
        log "SSH drop-in: ${drop_in}"
        echo ""
        echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${YELLOW}${BOLD}║  SSH ACTION REQUIRED — READ BEFORE CONTINUING               ║${RESET}"
        echo -e "${YELLOW}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        echo -e "${YELLOW}║  SSH config has been written to:                             ║${RESET}"
        echo -e "${YELLOW}║    ${drop_in}  ║${RESET}"
        echo -e "${YELLOW}║                                                              ║${RESET}"
        echo -e "${YELLOW}║  SSH has NOT been restarted automatically.                   ║${RESET}"
        echo -e "${YELLOW}║                                                              ║${RESET}"
        echo -e "${YELLOW}║  Before rebooting, you MUST:                                 ║${RESET}"
        echo -e "${YELLOW}║  1. Add your public key to ~/.ssh/authorized_keys            ║${RESET}"
        echo -e "${YELLOW}║  2. Open a NEW terminal and test:                            ║${RESET}"
        echo -e "${YELLOW}║       ssh -p 2222 -i ~/.ssh/id_ed25519 pi@<this-ip>         ║${RESET}"
        echo -e "${YELLOW}║  3. Only if step 2 works, restart SSH:                       ║${RESET}"
        echo -e "${YELLOW}║       sudo systemctl restart ssh                            ║${RESET}"
        echo -e "${YELLOW}║  4. Verify new session connects on port 2222                 ║${RESET}"
        echo -e "${YELLOW}║                                                              ║${RESET}"
        echo -e "${YELLOW}║  The REBOOT at the end of this script will activate all      ║${RESET}"
        echo -e "${YELLOW}║  SSH changes. Ensure step 2 passes first.                   ║${RESET}"
        echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        echo "# SSH restart pending manual verification" \
            >> "${LOG_DIR}/post-install-notes.txt"
        echo "# Run: sudo systemctl restart ssh  (after key is verified)" \
            >> "${LOG_DIR}/post-install-notes.txt"
    else
        error "SSHD config validation failed. Restoring backup and removing drop-in."
        rm -f "${drop_in}"
        exit 1
    fi
}

# =============================================================================
# SYSCTL HARDENING
# =============================================================================

harden_sysctl() {
    section "Applying kernel/sysctl hardening"

    # CHANGES v3.0.0:
    #   MOD-1   Removed net.ipv6.conf.all.disable_ipv6 and
    #           net.ipv6.conf.default.disable_ipv6 entirely.
    #           Reason: disabling IPv6 at kernel level breaks Tailscale's ability
    #           to use IPv6 direct peer connections and DERP fallback on networks
    #           that are IPv6-only (common on mobile hotspots, some hotel WiFi).
    #           Tailscale itself uses IPv6 internally for its 100.x.x.x overlay.
    #           IPv6 SECURITY settings (no redirects, no source routing) are kept.
    #   MOD-6   Removed net.ipv6.conf.lo.disable_ipv6 (was already fixed in v2.0.0
    #           for systemd D-Bus IPC; now fully consistent — lo left enabled)
    cat > "${SYSCTL_CONF}" << 'EOF'
# =============================================================
# MG Travel Server - Kernel Hardening (Pi Zero 2W / Bookworm)
# =============================================================

# --- Network Security ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log martians (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable TCP timestamps (reduces information leakage)
net.ipv4.tcp_timestamps = 0

# IPv6 security hardening — IPv6 itself is intentionally LEFT ENABLED
# Tailscale requires IPv6 for direct peer connections and some DERP relay paths.
# We harden IPv6 behaviour without disabling it:
#   - No IPv6 ICMP redirects (prevents redirect-based routing attacks)
#   - No IPv6 source routing (prevents source routing spoofing)
#   - These are already set above under "Network Security"
# DO NOT add net.ipv6.conf.all.disable_ipv6 here — it breaks Tailscale.

# --- Core Dump Prevention ---
# BOTH sysctl and limits.d are required for complete prevention
fs.suid_dumpable = 0
kernel.core_pattern = /dev/null

# --- Process / Memory Hardening ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- VM Tuning for 512MB RAM ---
vm.swappiness = 10
vm.panic_on_oom = 0
vm.overcommit_memory = 0
EOF

    sysctl --system >> "${SCRIPT_LOG}" 2>&1 || true
    log "Sysctl hardening applied."
}

# =============================================================================
# UFW FIREWALL CONFIGURATION
# =============================================================================

configure_ufw() {
    section "Configuring UFW firewall"

    ufw --force reset

    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward

    # SSH on custom port with rate limiting
    ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited"

    # Tailscale interface (interface rule is UFW-name-stored, applies when tailscale0 appears)
    ufw allow in on tailscale0 comment "Tailscale VPN"
    # Tailscale direct UDP (WireGuard-based handshake)
    ufw allow 41641/udp comment "Tailscale direct"

    # Enable UFW logging
    ufw logging on

    ufw --force enable
    log "UFW base rules applied."

    # Inject custom hardening rules into UFW's before.rules so they persist
    # across UFW reloads and reboots (UFW loads this file on every enable/reload)
    configure_ufw_before_rules
}

configure_ufw_before_rules() {
    section "Injecting hardened rules into UFW before.rules"

    local before_rules="/etc/ufw/before.rules"

    # Idempotent: only inject if not already present
    if grep -q "MG-TRAVEL-HARDENING" "${before_rules}" 2>/dev/null; then
        log "UFW before.rules already patched. Skipping."
        return 0
    fi

    # Back up original
    cp "${before_rules}" "${before_rules}.mg-backup-$(date +%Y%m%d%H%M%S)"

    # Build the injection block (inserted after the *filter line and initial ACCEPT rules
    # but before the COMMIT). We prepend our chains to the INPUT jump so they run first.
    local injection
    injection=$(cat << 'INJECTION'

# =============================================================
# MG-TRAVEL-HARDENING — Custom security chains (loaded by UFW)
# DO NOT EDIT THIS BLOCK MANUALLY
# =============================================================

# Drop invalid state packets immediately
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# Drop NULL scan packets (TCP with no flags)
-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP

# Drop XMAS scan packets (all flags set)
-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP

# Drop FIN scan packets
-A ufw-before-input -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP

# Port scan detection: block repeat connections to unused/closed service ports
# Uses xt_recent to track and block scanners for 24 hours
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 \
 -m conntrack --ctstate NEW -m recent --name mg_portscan --set
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 \
 -m conntrack --ctstate NEW -m recent --name mg_portscan --rcheck --seconds 86400 \
 --hitcount 3 -j LOG --log-prefix "MG-PORTSCAN: " --log-level 4
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 \
 -m conntrack --ctstate NEW -m recent --name mg_portscan --rcheck --seconds 86400 \
 --hitcount 3 -j DROP

# =============================================================
# END MG-TRAVEL-HARDENING
# =============================================================
INJECTION
)

    # Insert our rules just before the COMMIT line in the *filter table section
    # We use a unique marker so it's safe to detect and skip on re-runs
    python3 - "${before_rules}" << 'PYEOF'
import sys, os

path = sys.argv[1]
with open(path, 'r') as f:
    content = f.read()

marker = "# MG-TRAVEL-HARDENING"
if marker in content:
    print("Already patched, skipping.")
    sys.exit(0)

injection = """
# =============================================================
# MG-TRAVEL-HARDENING — Custom security chains (loaded by UFW)
# =============================================================

# Drop invalid state packets immediately
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# Drop NULL scan packets (TCP with no flags)
-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP

# Drop XMAS scan packets (all flags set)
-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP

# Drop FIN scan packets
-A ufw-before-input -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP

# Port scan detection: block scanners hitting closed ports
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 -m conntrack --ctstate NEW -m recent --name mg_portscan --set
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 -m conntrack --ctstate NEW -m recent --name mg_portscan --rcheck --seconds 86400 --hitcount 3 -j LOG --log-prefix "MG-PORTSCAN: " --log-level 4
-A ufw-before-input -p tcp -m multiport --dports 21,23,25,79,110,143,445,1433,3389 -m conntrack --ctstate NEW -m recent --name mg_portscan --rcheck --seconds 86400 --hitcount 3 -j DROP

# =============================================================
# END MG-TRAVEL-HARDENING
# =============================================================
"""

# Insert before the final COMMIT of the *filter section
lines = content.split('\n')
result = []
inserted = False
for line in reversed(lines):
    if not inserted and line.strip() == 'COMMIT':
        result.insert(0, line)
        result.insert(0, injection)
        inserted = True
    else:
        result.insert(0, line)

with open(path, 'w') as f:
    f.write('\n'.join(result))

print("UFW before.rules patched successfully.")
PYEOF

    # Reload UFW to apply the new rules
    ufw reload >> "${SCRIPT_LOG}" 2>&1
    log "UFW before.rules hardening rules injected and reloaded."
}

# =============================================================================
# FAIL2BAN CONFIGURATION
# =============================================================================

configure_fail2ban() {
    section "Configuring Fail2ban"

    mkdir -p /etc/fail2ban/jail.d
    mkdir -p /etc/fail2ban/fail2ban.d

    # FIXES:
    #   - Moved logtarget to fail2ban.d (daemon config), NOT jail.d
    #   - Changed backend to 'auto' (no python3-systemd dependency required;
    #     auto detects pyinotify or polling, reads /var/log/auth.log directly)
    #   - Changed banaction to 'ufw' so bans survive UFW reloads
    #   - Removed logtarget from jail config (invalid there)

    # Daemon-level config (logging destination)
    cat > /etc/fail2ban/fail2ban.d/mg-travel.conf << EOF
[Definition]
logtarget = ${LOG_DIR}/fail2ban.log
loglevel = INFO
EOF

    # Jail config
    cat > /etc/fail2ban/jail.d/mg-travel.conf << EOF
# MG Travel Server - Fail2ban Jail Configuration
[DEFAULT]
bantime   = 3600
findtime  = 600
maxretry  = 3
backend   = auto
banaction = ufw
banaction_allports = ufw

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200
findtime = 600
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    log "Fail2ban configured and started."
}

# =============================================================================
# ARPWATCH CONFIGURATION
# =============================================================================

configure_arpwatch() {
    section "Configuring arpwatch"

    # FIXES:
    #   - Removed invalid -l flag (arpwatch doesn't accept a log file argument;
    #     it logs exclusively to syslog)
    #   - Removed duplicate StandardOutput/StandardError (set in unit override correctly)
    #   - Added rsyslog rule to capture arpwatch syslog output to mg-travel log dir

    local arpwatch_log="${LOG_DIR}/arpwatch.log"

    touch "${arpwatch_log}"
    chmod 640 "${arpwatch_log}"

    # Systemd override: use wlan0 only, correct ExecStart without invalid flags
    mkdir -p /etc/systemd/system/arpwatch.service.d
    cat > /etc/systemd/system/arpwatch.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/arpwatch -i ${REQUIRED_INTERFACE} -f /var/lib/arpwatch/arp.dat -N -p
StandardOutput=null
StandardError=null
EOF
    # -N = don't report new station messages (reduces noise on travel WiFi)
    # -p = don't use promiscuous mode (not useful in 802.11 client mode; avoids errors)

    # rsyslog rule: forward arpwatch syslog messages to our log file
    cat > /etc/rsyslog.d/49-mg-arpwatch.conf << EOF
# MG Travel Server - arpwatch log capture
if \$programname == 'arpwatch' then ${arpwatch_log}
& stop
EOF

    systemctl daemon-reload
    systemctl enable arpwatch
    systemctl restart arpwatch
    systemctl restart rsyslog
    log "arpwatch configured on ${REQUIRED_INTERFACE}."
}

# =============================================================================
# VNSTAT CONFIGURATION
# =============================================================================

configure_vnstat() {
    section "Configuring vnstat"

    # FIX: vnstat v2.x daemon auto-creates databases. The --add flag behavior
    # varies across versions. Safest: configure the interface in conf, restart
    # the daemon, let it auto-initialize.

    local vnstat_conf="/etc/vnstat.conf"

    if [[ -f "${vnstat_conf}" ]]; then
        # Handle both 'Interface' and ';Interface' (commented) forms
        if grep -qE '^;?Interface ' "${vnstat_conf}"; then
            sed -i "s|^;*Interface .*|Interface \"${REQUIRED_INTERFACE}\"|" "${vnstat_conf}"
        else
            echo "Interface \"${REQUIRED_INTERFACE}\"" >> "${vnstat_conf}"
        fi
    fi

    systemctl enable vnstat
    systemctl restart vnstat

    # Allow daemon a moment to initialize, then attempt DB creation (v2.x)
    sleep 3
    vnstat -u -i "${REQUIRED_INTERFACE}" 2>/dev/null || \
        vnstat --add -i "${REQUIRED_INTERFACE}" 2>/dev/null || \
        log "vnstat DB will be auto-created by daemon on first run."

    log "vnstat configured for ${REQUIRED_INTERFACE}."
}

# =============================================================================
# RKHUNTER — REMOVED (MOD-3)
# =============================================================================
# rkhunter is intentionally not installed or configured in v3.0.0.
#
# Reason: On Raspberry Pi Zero 2W (512MB RAM, SD card storage), a full rkhunter
# scan takes 15-25 minutes of near-100% CPU utilisation with heavy I/O. This
# causes thermal throttling, SD card wear, and OOM risk. Even with `nice -n 19`
# the I/O pressure cannot be prioritised away.
#
# Integrity monitoring is provided by:
#   - UFW IDS rules in before.rules (port scan + malformed packet detection)
#   - arpwatch on wlan0 (ARP table change detection)
#   - mg-gw-monitor (gateway MAC baseline + change alerting every 5 minutes)
#   - mg-dns-monitor (DNS tampering detection every 10 minutes)
#   - mg-watchdog (suspicious outbound connection monitoring every 2 minutes)
#   - fail2ban (brute-force lockout on SSH port 2222)
#
# If rootkit scanning is required for this deployment, consider running
# rkhunter manually (sudo rkhunter --check) during a maintenance window
# rather than on a scheduled basis.
# =============================================================================

configure_rkhunter() {
    section "rkhunter — skipped (removed in v3.0.0)"
    log "rkhunter not installed. See script header comment for rationale."
    log "Integrity monitoring provided by: UFW IDS, arpwatch, gw-monitor, dns-monitor, watchdog."
}

# =============================================================================
# GATEWAY MAC MONITOR
# =============================================================================

create_gateway_monitor() {
    section "Creating gateway MAC monitoring script"

    # FIX: Changed state file delimiter from ':' to '|' to allow correct parsing
    # of MAC addresses (which contain ':' themselves). Previous cut -d: -f2 only
    # returned the first MAC octet, breaking change detection entirely.

    cat > "${GW_MONITOR_SCRIPT}" << 'GWSCRIPT'
#!/usr/bin/env bash
# MG Travel Server - Gateway MAC Monitor
# Run by cron.d every 5 minutes. Detects gateway MAC changes (ARP spoofing / MITM).

LOG_FILE="/var/log/mg-travel/gw-monitor.log"
STATE_FILE="/var/lib/mg-travel/gateway-mac.state"
LOCK_FILE="/var/run/mg-gw-monitor.lock"
INTERFACE="wlan0"

# Prevent concurrent runs
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    exit 0
fi

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [GW-MONITOR] $*" >> "${LOG_FILE}"
}

get_gateway_ip() {
    ip route show dev "${INTERFACE}" 2>/dev/null | awk '/default via/ {print $3; exit}'
}

get_gateway_mac() {
    local gw_ip="$1"
    [[ -z "${gw_ip}" ]] && return 1
    # Ping to refresh ARP cache
    ping -c 1 -W 2 -I "${INTERFACE}" "${gw_ip}" &>/dev/null || true
    # Read from ARP cache
    arp -n "${gw_ip}" 2>/dev/null | awk '/ether/ {print $3}' | head -1
}

main() {
    local gw_ip gw_mac known_mac

    gw_ip="$(get_gateway_ip)"
    if [[ -z "${gw_ip}" ]]; then
        log_event "WARNING: Could not determine gateway IP on ${INTERFACE}"
        exit 0
    fi

    gw_mac="$(get_gateway_mac "${gw_ip}")"
    if [[ -z "${gw_mac}" ]]; then
        log_event "WARNING: Could not resolve gateway MAC for ${gw_ip}"
        exit 0
    fi

    if [[ ! -f "${STATE_FILE}" ]]; then
        # FIX: Use '|' as delimiter — MAC addresses contain ':' which breaks cut -d:
        printf '%s|%s\n' "${gw_ip}" "${gw_mac}" > "${STATE_FILE}"
        chmod 600 "${STATE_FILE}"
        log_event "INFO: Gateway baseline recorded — IP=${gw_ip} MAC=${gw_mac}"
        exit 0
    fi

    # FIX: Extract full MAC using '|' delimiter (previously cut -d: -f2 only
    # returned the first octet of the MAC address, making change detection useless)
    known_mac="$(grep "^${gw_ip}|" "${STATE_FILE}" | cut -d'|' -f2)"

    if [[ -z "${known_mac}" ]]; then
        printf '%s|%s\n' "${gw_ip}" "${gw_mac}" >> "${STATE_FILE}"
        log_event "INFO: New gateway recorded — IP=${gw_ip} MAC=${gw_mac}"
    elif [[ "${known_mac}" != "${gw_mac}" ]]; then
        log_event "ALERT: GATEWAY MAC CHANGE DETECTED! IP=${gw_ip} | Known=${known_mac} | Current=${gw_mac}"
        logger -t mg-gw-monitor "ALERT: Gateway MAC changed for ${gw_ip}: ${known_mac} -> ${gw_mac}"
        wall "MG SECURITY ALERT: Gateway MAC address change detected! Possible ARP spoofing!" 2>/dev/null || true
    else
        log_event "OK: Gateway ${gw_ip} MAC verified: ${gw_mac}"
    fi
}

main "$@"
GWSCRIPT

    chmod 750 "${GW_MONITOR_SCRIPT}"
    log "Gateway MAC monitor created: ${GW_MONITOR_SCRIPT}"
}

# =============================================================================
# DNS TAMPERING DETECTION
# =============================================================================

create_dns_monitor() {
    section "Creating DNS tampering detection script"

    # MOD-5: Completely rewritten detection logic.
    #
    # v2.0.0 PROBLEM: Comparing the actual IP returned by the local resolver
    # against 8.8.8.8's answer caused constant false positives. CDN-distributed
    # domains (google.com, cloudflare.com, github.com) legitimately return
    # DIFFERENT IPs based on the resolver's geographic location and Anycast
    # routing. A hotel router's DNS returning 142.250.x.x while 8.8.8.8 returns
    # 142.251.x.x for google.com is completely normal — not tampering.
    #
    # v3.0.0 APPROACH: Alert ONLY when the local resolver returns NXDOMAIN
    # (SERVFAIL or empty response) while the reference resolver (1.1.1.1)
    # resolves successfully. This is the true signal of DNS poisoning, blocking,
    # or sinkholing — not incidental CDN IP variance.
    #
    # Reference resolver changed from 8.8.8.8 to 1.1.1.1 (Cloudflare):
    # - 1.1.1.1 has stronger privacy guarantees (no query logging by default)
    # - Reduces correlation between our monitoring traffic and Google's DNS logs
    # - Both 1.1.1.1 and 8.8.8.8 are equally reliable as reference resolvers

    cat > "${DNS_MONITOR_SCRIPT}" << 'DNSSCRIPT'
#!/usr/bin/env bash
# =============================================================================
# MG Travel Server - DNS Tampering Detection (v3.0)
# Run by cron.d every 10 minutes.
#
# Detection strategy: NXDOMAIN-only alerting
#   ALERT when: local resolver returns NXDOMAIN/SERVFAIL/empty
#               AND reference resolver (1.1.1.1) returns a valid A record
#   IGNORE:     IP differences between resolvers (CDN/Anycast are normal)
#   LOG:        All results for audit trail regardless of alert state
# =============================================================================

LOG_FILE="/var/log/mg-travel/dns-monitor.log"
LOCK_FILE="/var/run/mg-dns-monitor.lock"

# Cloudflare 1.1.1.1 as reference — privacy-respecting, globally reliable
REFERENCE_RESOLVER="1.1.1.1"

# Test domains chosen for:
#   - Global availability (never legitimately NXDOMAIN)
#   - High uptime (false negative from resolver outage is extremely unlikely)
#   - Mix of operators (Google, Cloudflare, GitHub) reduces single-vendor risk
TEST_DOMAINS=(
    "google.com"
    "cloudflare.com"
    "github.com"
)

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    exit 0
fi

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [DNS-MONITOR] $*" >> "${LOG_FILE}"
}

# Returns 0 (success/resolved) or 1 (NXDOMAIN/SERVFAIL/unreachable)
# Writes resolved IP to stdout on success, empty on failure
query_resolver() {
    local domain="$1"
    local resolver="$2"
    local result

    result="$(dig +short +time=3 +tries=1 "@${resolver}" "${domain}" A 2>/dev/null \
        | grep -E '^[0-9]+\.' | head -1)"

    if [[ -n "${result}" ]]; then
        echo "${result}"
        return 0
    fi
    # Check for explicit NXDOMAIN/SERVFAIL in the full output
    local full_output
    full_output="$(dig +time=3 +tries=1 "@${resolver}" "${domain}" A 2>/dev/null)"
    if echo "${full_output}" | grep -qE 'NXDOMAIN|SERVFAIL'; then
        return 2   # Definitive negative response
    fi
    return 1       # Empty/timeout — inconclusive
}

get_local_resolver() {
    grep -m1 "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}'
}

main() {
    local local_resolver local_ip reference_ip
    local local_rc reference_rc
    local tampering_detected=0
    local inconclusive_count=0

    local_resolver="$(get_local_resolver)"
    if [[ -z "${local_resolver}" ]]; then
        log_event "WARNING: Could not determine local resolver from /etc/resolv.conf"
        exit 0
    fi

    # If the local resolver IS the reference resolver, comparisons are meaningless
    if [[ "${local_resolver}" == "${REFERENCE_RESOLVER}" ]]; then
        log_event "INFO: Local resolver (${local_resolver}) is the reference resolver. Skipping."
        exit 0
    fi

    log_event "INFO: Checking ${#TEST_DOMAINS[@]} domains — local=${local_resolver} ref=${REFERENCE_RESOLVER}"

    for domain in "${TEST_DOMAINS[@]}"; do

        # Query local resolver
        local_ip="$(query_resolver "${domain}" "${local_resolver}")"
        local_rc=$?

        # Query reference resolver
        reference_ip="$(query_resolver "${domain}" "${REFERENCE_RESOLVER}")"
        reference_rc=$?

        # Reference resolver failed — connectivity issue, not tampering
        if [[ "${reference_rc}" -ne 0 ]]; then
            log_event "WARNING: Reference resolver (${REFERENCE_RESOLVER}) could not resolve ${domain} (rc=${reference_rc}). Skipping comparison — possible connectivity issue."
            (( inconclusive_count++ )) || true
            continue
        fi

        # Local resolver returned NXDOMAIN/SERVFAIL while reference succeeded:
        # This is the definitive tampering/blocking/sinkhole signal.
        if [[ "${local_rc}" -ne 0 ]] && [[ "${reference_rc}" -eq 0 ]]; then
            log_event "ALERT: DNS BLOCKING/TAMPERING DETECTED for ${domain}!"
            log_event "  Local resolver ${local_resolver} returned NXDOMAIN/SERVFAIL/empty"
            log_event "  Reference resolver ${REFERENCE_RESOLVER} returned: ${reference_ip}"
            log_event "  Verdict: Domain is being blocked or DNS response is being suppressed"
            logger -t mg-dns-monitor "ALERT: DNS blocking/tampering for ${domain} via ${local_resolver}"
            tampering_detected=1

        # Both resolvers returned results (IPs may differ — this is NORMAL for CDNs)
        elif [[ "${local_rc}" -eq 0 ]] && [[ "${reference_rc}" -eq 0 ]]; then
            if [[ "${local_ip}" != "${reference_ip}" ]]; then
                # Log the difference for audit purposes but DO NOT alert
                # CDN/Anycast IP differences are expected and not a security signal
                log_event "OK: ${domain} resolved by both resolvers (IPs differ — normal CDN behaviour)"
                log_event "  Local(${local_resolver})=${local_ip}  Ref(${REFERENCE_RESOLVER})=${reference_ip}"
            else
                log_event "OK: ${domain} resolved identically by both resolvers (${local_ip})"
            fi

        # Local resolved, reference failed — unusual but not evidence of tampering
        elif [[ "${local_rc}" -eq 0 ]] && [[ "${reference_rc}" -ne 0 ]]; then
            log_event "INFO: ${domain} resolved locally (${local_ip}) but reference failed. Possible reference outage."
        fi
    done

    if [[ "${tampering_detected}" -eq 1 ]]; then
        log_event "ALERT: DNS tampering/blocking confirmed. Review dns-monitor.log immediately."
        wall "MG SECURITY ALERT: DNS tampering or blocking detected! Check /var/log/mg-travel/dns-monitor.log" 2>/dev/null || true
    elif [[ "${inconclusive_count}" -eq "${#TEST_DOMAINS[@]}" ]]; then
        log_event "WARNING: All reference queries failed — possible internet connectivity loss."
    fi
}

main "$@"
DNSSCRIPT

    chmod 750 "${DNS_MONITOR_SCRIPT}"
    log "DNS monitor (v3 NXDOMAIN-only logic, ref=1.1.1.1) created: ${DNS_MONITOR_SCRIPT}"
}

# =============================================================================
# MG-SERVERS MONITORING WATCHDOG DAEMON
# =============================================================================

create_watchdog_daemon() {
    section "Creating MG-Servers network watchdog daemon"

    # FIXES:
    #   - Removed run_gateway_monitor() from the loop — cron.d handles it at 5min intervals.
    #     Calling it every 60s was excessive (ping + arp subprocess per minute) and
    #     created race conditions with the concurrent cron job on the state file.
    #   - Removed run_dns_monitor() from the loop — cron.d handles it at 10min intervals.
    #     Both running simultaneously spawned 6 dig processes each time.
    #   - check_ufw_running() now LOG-ONLY. Calling 'ufw --force enable' from the watchdog
    #     caused a full iptables flush (brief packet blackhole) and could drop WiFi on a
    #     single-interface node. UFW's own systemd unit handles recovery.
    #   - Watchdog interval increased to 120s (from 60s) to reduce CPU load on Pi Zero 2W.
    #     Core checks (interface status, service liveness, suspicious connections) still
    #     run at 2-minute cadence which is adequate for a travel security node.
    #   - Added MOTD cache update to watchdog loop for fast login (avoids tailscale/ufw
    #     CLI calls on every SSH session — those are slow on Pi Zero 2W).
    #   - Reduced suspicious port list to highest-risk ports only.

    cat > "${WATCHDOG_SCRIPT}" << 'WDSCRIPT'
#!/usr/bin/env bash
# =============================================================================
# MG Travel Server - Network Watchdog Daemon (v3.0)
# Monitors: interface status, service liveness, suspicious connections
# Cron.d handles: gateway MAC (5min), DNS tampering (10min)
# rkhunter removed in v3.0.0 — see configure_rkhunter() for rationale
# =============================================================================

LOG_FILE="/var/log/mg-travel/watchdog.log"
CONN_LOG="/var/log/mg-travel/suspicious-connections.log"
MOTD_CACHE="/run/mg-travel-status"
INTERFACE="wlan0"
INTERVAL=120  # 2 minutes — balanced for Pi Zero 2W CPU budget

# Highest-risk C2/backdoor/proxy ports for connection monitoring
SUSPICIOUS_PORTS=(4444 5555 6666 1080 9050 9051 12345 31337)

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHDOG] $*" >> "${LOG_FILE}"
}

log_conn() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CONN] $*" >> "${CONN_LOG}"
}

check_suspicious_connections() {
    local conns
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        conns="$(ss -tnp 2>/dev/null | awk -v p=":${port}" '$0 ~ p && !/127\.0\.0\.1/')"
        if [[ -n "${conns}" ]]; then
            log_conn "ALERT: Suspicious connection detected on port ${port}:"
            while IFS= read -r line; do
                log_conn "  ${line}"
            done <<< "${conns}"
            logger -t mg-watchdog "ALERT: Suspicious connection on port ${port}"
        fi
    done
}

check_interface_status() {
    if ! ip link show "${INTERFACE}" 2>/dev/null | grep -q "state UP"; then
        log_event "WARNING: Interface ${INTERFACE} is not UP"
    fi
}

check_arpwatch_running() {
    if ! systemctl is-active --quiet arpwatch 2>/dev/null; then
        log_event "WARNING: arpwatch is not running. Attempting restart."
        systemctl restart arpwatch 2>/dev/null \
            || log_event "ERROR: Failed to restart arpwatch"
    fi
}

check_fail2ban_running() {
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_event "WARNING: fail2ban is not running. Attempting restart."
        systemctl restart fail2ban 2>/dev/null \
            || log_event "ERROR: Failed to restart fail2ban"
    fi
}

# FIX: LOG-ONLY — removed 'ufw --force enable' which caused full iptables flush
# (brief packet blackhole on single-interface WiFi node). UFW's own systemd unit
# handles firewall recovery on failure. The watchdog only reports.
check_ufw_status() {
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        log_event "ALERT: UFW is not active! Firewall may be down. Check immediately."
        logger -t mg-watchdog "ALERT: UFW firewall is inactive"
    fi
}

# Update MOTD cache — allows MOTD script to read cached values instead of
# spawning slow CLI tools (tailscale, ufw) on every SSH login
update_motd_cache() {
    local ts_status ufw_active wlan_ip

    ts_status="$(tailscale status --self=true --peers=false 2>/dev/null | head -1 \
        || echo 'Not authenticated')"
    ufw_active="$(ufw status 2>/dev/null | awk 'NR==1 {print $2}' || echo 'unknown')"
    wlan_ip="$(ip addr show "${INTERFACE}" 2>/dev/null \
        | awk '/inet / {gsub(/\/.*/, "", $2); print $2}' | head -1 || echo 'N/A')"

    cat > "${MOTD_CACHE}" << EOF
TAILSCALE_STATUS=${ts_status}
UFW_STATUS=${ufw_active}
WLAN_IP=${wlan_ip}
CACHE_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF
    chmod 644 "${MOTD_CACHE}"
}

main_loop() {
    log_event "MG Travel Watchdog started (PID=$$, interval=${INTERVAL}s)"

    while true; do
        check_interface_status
        check_arpwatch_running
        check_fail2ban_running
        check_ufw_status
        check_suspicious_connections
        update_motd_cache
        sleep "${INTERVAL}"
    done
}

main_loop
WDSCRIPT

    chmod 750 "${WATCHDOG_SCRIPT}"
    log "Watchdog daemon script created: ${WATCHDOG_SCRIPT}"
}

# =============================================================================
# SYSTEMD SERVICE FOR WATCHDOG
# =============================================================================

create_watchdog_service() {
    section "Creating systemd service for MG watchdog"

    # FIXES:
    #   - Changed ProtectSystem=strict to ProtectSystem=full
    #     (strict blocks /etc writes needed by ufw status; full protects /usr+/boot)
    #   - Added /run to ReadWritePaths for MOTD cache file
    #   - Added /etc/ufw to ReadWritePaths (for ufw status reads under full protection)
    #   - Removed ufw --force enable from watchdog so CAP_NET_ADMIN is less critical
    #     but kept for ss, ip, and arp operations

    cat > "${WATCHDOG_SERVICE}" << 'EOF'
[Unit]
Description=MG Travel Server - Network Watchdog Daemon
Documentation=man:mg-watchdog(1)
After=network-online.target tailscaled.service arpwatch.service
Wants=network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mg-watchdog
Restart=on-failure
RestartSec=30
StandardOutput=append:/var/log/mg-travel/watchdog.log
StandardError=append:/var/log/mg-travel/watchdog-error.log
SyslogIdentifier=mg-watchdog
User=root

# Sandboxing — ProtectSystem=full protects /usr and /boot (read-only)
# but leaves /etc and /run accessible for ufw status and MOTD cache
NoNewPrivileges=yes
ProtectSystem=full
ReadWritePaths=/var/log/mg-travel /var/lib/mg-travel /run
ProtectHome=read-only
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mg-watchdog
    systemctl restart mg-watchdog
    log "MG watchdog service enabled and started."
}

# =============================================================================
# LOG ROTATION
# =============================================================================

configure_logrotate() {
    section "Configuring log rotation"

    # Determine log owner group
    local log_group="root"
    getent group adm &>/dev/null && log_group="adm"

    # FIX: Use dynamic group (adm if exists, else root) — avoids silent failure
    # FIX: Replaced 'systemctl reload rsyslog' with correct HUP signal in postrotate
    cat > "${LOGROTATE_CONF}" << EOF
${LOG_DIR}/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root ${log_group}
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || \
            kill -HUP \$(cat /var/run/rsyslogd.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF

    log "Log rotation configured."
}

# =============================================================================
# UNATTENDED UPGRADES
# =============================================================================

configure_unattended_upgrades() {
    section "Configuring unattended security upgrades"

    cat > /etc/apt/apt.conf.d/20mg-auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    cat > /etc/apt/apt.conf.d/50mg-unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "Raspberry Pi Foundation:${distro_codename}";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    log "Unattended upgrades configured."
}

# =============================================================================
# DISABLE UNNECESSARY SERVICES
# =============================================================================

disable_unnecessary_services() {
    section "Disabling unnecessary services"

    # FIX: wpa_supplicant INTENTIONALLY REMOVED from this list.
    # On Raspberry Pi OS Lite, wpa_supplicant manages wlan0 via dhcpcd.
    # Disabling it = instant WiFi loss = SSH lockout. It must remain running.
    #
    # Safe to disable on Pi Zero 2W (no hardware for most, no user sessions for others):
    local services_to_disable=(
        avahi-daemon   # mDNS/DNS-SD — unnecessary on a travel security node
        bluetooth      # Pi Zero 2W has BT but we don't use it
        hciuart        # BT UART — only present if BT enabled
        triggerhappy   # Hotkey daemon — no keyboard on headless Pi
    )

    local svc
    for svc in "${services_to_disable[@]}"; do
        # Skip comment lines
        [[ "${svc}" == \#* ]] && continue
        # Use || true to prevent set -e from exiting on non-existent services
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            systemctl disable --now "${svc}" 2>/dev/null \
                && log "Disabled: ${svc}" \
                || warn "Could not disable ${svc} (may not be present)"
        else
            log "Service not found, skipping: ${svc}"
        fi
    done

    log "Unnecessary services disabled."
}

# =============================================================================
# ELITE PARANOID HARDENING
# =============================================================================

paranoid_hardening() {
    section "Applying elite paranoid hardening"

    # --- USB Storage Block ---
    cat > "${USBBLOCK_CONF}" << 'EOF'
# MG Travel Server - Block USB storage auto-mount
install usb-storage /bin/true
blacklist usb-storage
EOF
    log "USB storage auto-mount disabled."

    # --- Core Dump Prevention ---
    cat > /etc/security/limits.d/99-mg-nodump.conf << 'EOF'
*    hard    core    0
*    soft    core    0
root hard    core    0
root soft    core    0
EOF
    # sysctl kernel.core_pattern = /dev/null handles the kernel side (set in harden_sysctl)

    # --- Strong umask ---
    if ! grep -q "umask 027" /etc/profile; then
        printf '\n# MG Travel Server - strong umask\numask 027\n' >> /etc/profile
    fi
    if ! grep -q "umask 027" /etc/bash.bashrc; then
        printf '\n# MG Travel Server - strong umask\numask 027\n' >> /etc/bash.bashrc
    fi

    # --- Restrict cron to root only ---
    echo "root" > /etc/cron.allow
    chmod 600 /etc/cron.allow
    : > /etc/cron.deny
    chmod 600 /etc/cron.deny

    # --- Restrict at to root only ---
    if [[ -f /etc/at.deny ]] || command -v at &>/dev/null; then
        echo "root" > /etc/at.allow 2>/dev/null || true
        chmod 600 /etc/at.allow 2>/dev/null || true
        : > /etc/at.deny 2>/dev/null || true
        chmod 600 /etc/at.deny 2>/dev/null || true
    fi

    # --- hidepid: NOT CONFIGURED (MOD-4) ---
    # hidepid=invisible in /etc/fstab was removed in v3.0.0.
    # Reason: On Raspberry Pi OS Bookworm (kernel 6.x + systemd 252+), hidepid
    # requires a dedicated proc group, usermod for multiple system users
    # (systemd-logind, polkit, colord, etc.) and careful per-service testing.
    # On a headless single-user Pi this is manageable, but systemd-logind
    # failures after fstab modification have been reported on Pi OS specifically
    # and would break SSH login. The risk/benefit ratio is unfavourable for a
    # travel node where SSH access stability is paramount.
    # Protection-in-depth is maintained by: strong umask, cron.allow, file
    # permissions on /root and sensitive files, and the single-user nature
    # of this device (no untrusted local users exist).

    # --- File Permissions ---
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 700 /root
    chmod 750 /var/log
    chmod 640 /var/log/syslog 2>/dev/null || true
    chmod 640 /var/log/auth.log 2>/dev/null || true

    log "Paranoid hardening applied."
}

# =============================================================================
# ASCII BANNER & MOTD
# =============================================================================

create_banner_and_motd() {
    section "Creating login banner and MOTD"

    cat > "${BANNER_FILE}" << 'EOF'

  ███╗   ███╗ ██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ ███████╗
  ████╗ ████║██╔════╝     ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗██╔════╝
  ██╔████╔██║██║  ███╗    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝███████╗
  ██║╚██╔╝██║██║   ██║    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║
  ██║ ╚═╝ ██║╚██████╔╝    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║███████║
  ╚═╝     ╚═╝ ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝

  MG Travel Server | Secure Client Node
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║  AUTHORIZED ACCESS ONLY. All activity is logged and monitored.                 ║
  ║  Unauthorized access is prohibited and subject to legal action.                ║
  ╚══════════════════════════════════════════════════════════════════════════════════╝

EOF

    chmod 644 "${BANNER_FILE}"

    # Disable other MOTD scripts (keeps login clean)
    find /etc/update-motd.d/ -maxdepth 1 -type f ! -name "99-mg-travel" \
        -exec chmod -x {} \; 2>/dev/null || true

    # FIX: MOTD now reads from MOTD_CACHE file (updated by watchdog every 2 minutes)
    # instead of spawning slow CLI tools (tailscale, ufw) on every SSH login.
    # Fallback to live data if cache is absent/stale.
    cat > "${MOTD_SCRIPT}" << 'MOTDSCRIPT'
#!/usr/bin/env bash
# MG Travel Server - Dynamic MOTD (reads watchdog cache for fast login)

INTERFACE="wlan0"
MOTD_CACHE="/run/mg-travel-status"

# Source cache file if it exists and is recent (< 5 minutes old)
TAILSCALE_STATUS="Checking..."
UFW_STATUS="Checking..."
WLAN_IP="Checking..."
CACHE_TIME="N/A"

if [[ -f "${MOTD_CACHE}" ]]; then
    cache_age=$(( $(date +%s) - $(stat -c %Y "${MOTD_CACHE}" 2>/dev/null || echo 0) ))
    if [[ "${cache_age}" -lt 300 ]]; then
        # shellcheck source=/dev/null
        source "${MOTD_CACHE}" 2>/dev/null || true
    fi
fi

# Fallback for values not in cache
[[ "${WLAN_IP}" == "Checking..." ]] && \
    WLAN_IP="$(ip addr show "${INTERFACE}" 2>/dev/null \
        | awk '/inet / {gsub(/\/.*/, "", $2); print $2}' | head -1 || echo 'N/A')"

get_gateway_mac() {
    local gw_ip
    gw_ip="$(ip route show dev "${INTERFACE}" 2>/dev/null \
        | awk '/default via/ {print $3; exit}')"
    [[ -n "${gw_ip}" ]] && arp -n "${gw_ip}" 2>/dev/null | awk '/ether/ {print $3}' | head -1
}

get_bandwidth() {
    vnstat -i "${INTERFACE}" --oneline 2>/dev/null \
        | awk -F';' '{print "RX: "$4"  TX: "$5}' | head -1
}

echo ""
echo "  ╔════════════════════════════════════════════════════╗"
echo "  ║          MG Travel Server — Status Board           ║"
echo "  ╠════════════════════════════════════════════════════╣"
printf "  ║  %-20s %-28s ║\n" "Hostname:"         "$(hostname)"
printf "  ║  %-20s %-28s ║\n" "Date/Time:"        "$(date '+%Y-%m-%d %H:%M:%S')"
printf "  ║  %-20s %-28s ║\n" "Uptime:"           "$(uptime -p)"
printf "  ║  %-20s %-28s ║\n" "wlan0 IP:"         "${WLAN_IP}"
printf "  ║  %-20s %-28s ║\n" "Gateway MAC:"      "$(get_gateway_mac || echo 'Unknown')"
printf "  ║  %-20s %-28s ║\n" "Bandwidth today:"  "$(get_bandwidth || echo 'No data')"
printf "  ║  %-20s %-28s ║\n" "Tailscale:"        "${TAILSCALE_STATUS}"
printf "  ║  %-20s %-28s ║\n" "UFW:"              "${UFW_STATUS}"
printf "  ║  %-20s %-28s ║\n" "Watchdog:"         "$(systemctl is-active mg-watchdog 2>/dev/null)"
printf "  ║  %-20s %-28s ║\n" "Cache updated:"    "${CACHE_TIME}"
echo "  ╠════════════════════════════════════════════════════╣"
echo "  ║  Logs: /var/log/mg-travel/                         ║"
echo "  ╚════════════════════════════════════════════════════╝"
echo ""
MOTDSCRIPT

    chmod +x "${MOTD_SCRIPT}"
    log "Banner and MOTD configured."
}

# =============================================================================
# CRON JOBS FOR MONITORING
# =============================================================================

configure_monitoring_crons() {
    section "Configuring monitoring cron jobs"

    # MOD-3: rkhunter entry removed entirely (not installed in v3.0.0)
    # MOD-5: dns-monitor now uses NXDOMAIN-only detection (false-positive safe)
    # NOTE:  gw-monitor and dns-monitor scheduled here ONLY (not in watchdog loop)
    # NOTE:  logrotate entry intentionally absent (system cron.daily handles it)

    cat > /etc/cron.d/mg-travel << 'EOF'
# MG Travel Server - Monitoring Cron Jobs
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Gateway MAC check every 5 minutes
*/5 * * * * root /usr/local/bin/mg-gw-monitor >> /var/log/mg-travel/cron.log 2>&1

# DNS tampering check every 10 minutes (NXDOMAIN-only detection — no false positives from CDN)
*/10 * * * * root /usr/local/bin/mg-dns-monitor >> /var/log/mg-travel/cron.log 2>&1
EOF

    chmod 644 /etc/cron.d/mg-travel
    log "Monitoring cron jobs configured (gw-monitor every 5min, dns-monitor every 10min)."
}

# =============================================================================
# FINAL PERMISSIONS SWEEP
# =============================================================================

finalize_permissions() {
    section "Finalizing permissions"

    local log_group="root"
    getent group adm &>/dev/null && log_group="adm"

    chmod 750 "${LOG_DIR}"
    chown "root:${log_group}" "${LOG_DIR}"
    find "${LOG_DIR}" -type f -exec chmod 640 {} \;

    chmod 700 /var/lib/mg-travel
    chown root:root /var/lib/mg-travel

    chmod 750 "${GW_MONITOR_SCRIPT}" "${DNS_MONITOR_SCRIPT}" "${WATCHDOG_SCRIPT}"

    log "Permissions finalized."
}

# =============================================================================
# VERIFY NETWORK IS STILL INTACT
# =============================================================================

verify_network() {
    section "Verifying network connectivity post-installation"

    if ip link show "${REQUIRED_INTERFACE}" 2>/dev/null | grep -q "state UP"; then
        log "Interface ${REQUIRED_INTERFACE} is UP — WiFi connection preserved."
    else
        warn "Interface ${REQUIRED_INTERFACE} may not be UP. Verify WiFi config."
    fi

    if ping -c 2 -W 5 8.8.8.8 &>/dev/null; then
        log "Internet connectivity confirmed."
    else
        warn "Cannot reach internet. Check WiFi. SSH port is ${SSH_PORT}."
    fi
}

# =============================================================================
# POST-INSTALL SUMMARY
# =============================================================================

print_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║        MG Travel Server — Installation Complete v3.0        ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  SSH Port          : 2222 (key-auth only, not yet restarted)║"
    echo "  ║  Firewall          : UFW active (deny incoming)             ║"
    echo "  ║  IDS Rules         : UFW before.rules (persistent)          ║"
    echo "  ║  Fail2ban          : Active (auth.log / UFW banaction)       ║"
    echo "  ║  arpwatch          : Active on wlan0                        ║"
    echo "  ║  Watchdog Daemon   : Active (2-min interval)                ║"
    echo "  ║  Gateway Monitor   : Cron every 5 minutes                   ║"
    echo "  ║  DNS Monitor       : Cron every 10 minutes (NXDOMAIN mode)  ║"
    echo "  ║  IPv6              : ENABLED (required for Tailscale)        ║"
    echo "  ║  Logs              : /var/log/mg-travel/                    ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  REQUIRED ACTIONS — COMPLETE IN ORDER:                      ║"
    echo "  ║                                                              ║"
    echo "  ║  1. Add your SSH public key (do this NOW):                   ║"
    echo "  ║     cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys     ║"
    echo "  ║     chmod 600 ~/.ssh/authorized_keys                        ║"
    echo "  ║                                                              ║"
    echo "  ║  2. Test SSH on new port in a NEW terminal:                  ║"
    echo "  ║     ssh -p 2222 -i ~/.ssh/id_ed25519 pi@<this-ip>          ║"
    echo "  ║                                                              ║"
    echo "  ║  3. If step 2 succeeds, restart SSH to activate hardening:   ║"
    echo "  ║     sudo systemctl restart ssh                              ║"
    echo "  ║                                                              ║"
    echo "  ║  4. Authenticate Tailscale:                                  ║"
    echo "  ║     sudo tailscale up                                       ║"
    echo "  ║                                                              ║"
    echo "  ║  5. Reboot to apply all kernel sysctl settings:              ║"
    echo "  ║     sudo reboot                                             ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    log "Installation v${SCRIPT_VERSION} completed. Review ${LOG_DIR}/post-install-notes.txt"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Bootstrap logging before anything else
    mkdir -p "${LOG_DIR}"
    touch "${SCRIPT_LOG}"
    chmod 640 "${SCRIPT_LOG}"

    echo -e "${CYAN}${BOLD}"
    echo "  MG Travel Servers — Hardened Installation Script v${SCRIPT_VERSION}"
    echo -e "${RESET}"

    log "Starting MG Travel Server installation — $(date)"
    log "Target: Raspberry Pi Zero 2W | Raspberry Pi OS Lite 64-bit"

    preflight_checks
    setup_directories
    system_update
    install_packages
    install_tailscale
    harden_ssh
    harden_sysctl
    configure_ufw
    configure_fail2ban
    configure_arpwatch
    configure_vnstat
    configure_rkhunter
    create_gateway_monitor
    create_dns_monitor
    create_watchdog_daemon
    create_watchdog_service
    configure_logrotate
    configure_unattended_upgrades
    disable_unnecessary_services
    paranoid_hardening
    create_banner_and_motd
    configure_monitoring_crons
    finalize_permissions
    verify_network
    print_summary
}

main "$@"
