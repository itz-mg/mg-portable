#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# MG Travel — SD Backup Station
# MG Servers Production Install Script
# Target: Raspberry Pi Zero 2 W / Raspberry Pi OS Lite (Debian)
# User: mg | App User: mgtravel | Hostname: mgtravel
# =============================================================================

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
APP_NAME="mgtravel"
APP_DIR="/opt/mgtravel"
APP_USER="mgtravel"
APP_PORT=5000
LOG_TAG="[MG Travel]"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"
NGINX_CONF="/etc/nginx/sites-available/mgtravel"
SERVICE_FILE="/etc/systemd/system/mgtravel.service"
LOGROTATE_CONF="/etc/logrotate.d/mgtravel"
UDEV_RULE="/etc/udev/rules.d/99-mgtravel-sd.rules"
JOURNAL_CONF="/etc/systemd/journald.conf.d/mgtravel.conf"
HOSTNAME_NEW="mgtravel"

# ─── HELPERS ──────────────────────────────────────────────────────────────────
log()  { echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_TAG} $*"; }
ok()   { log "✔  $*"; }
info() { log "➜  $*"; }
warn() { log "⚠  $*"; }
die()  { log "✖  $*"; exit 1; }

backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp -a "$f" "${f}${BACKUP_SUFFIX}"
        ok "Backed up $f → ${f}${BACKUP_SUFFIX}"
    fi
}

ensure_dir() {
    local d="$1" owner="${2:-root:root}" mode="${3:-750}"
    if [[ ! -d "$d" ]]; then
        mkdir -p "$d"
    fi
    chown "$owner" "$d"
    chmod "$mode" "$d"
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# ─── PRE-FLIGHT CHECKS ────────────────────────────────────────────────────────
preflight_checks() {
    info "Running pre-flight checks..."

    [[ $EUID -eq 0 ]] || die "Script must be run as root. Use: sudo ./install.sh"

    [[ -f /etc/debian_version ]] || die "This script requires a Debian-based OS."

    id mg &>/dev/null || die "User 'mg' does not exist on this system."

    local avail_mb
    avail_mb=$(df /opt --output=avail -BM 2>/dev/null | tail -1 | tr -d 'M ')
    [[ "$avail_mb" -ge 512 ]] || die "Less than 512 MB free on /opt. Aborting."

    ok "Pre-flight checks passed."
}

# ─── SYSTEM UPDATE ────────────────────────────────────────────────────────────
system_update() {
    info "Updating package lists..."
    apt-get update -qq

    info "Upgrading installed packages (safe upgrade)..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold"

    ok "System packages up to date."
}

# ─── PACKAGE INSTALLATION ─────────────────────────────────────────────────────
install_packages() {
    local pkgs=(
        python3 python3-pip python3-venv
        rsync udev nginx git
        fail2ban ufw avahi-daemon
        gunicorn
        curl ca-certificates
        logrotate
        util-linux
    )

    info "Installing required system packages..."
    for pkg in "${pkgs[@]}"; do
        if pkg_installed "$pkg"; then
            ok "$pkg already installed."
        else
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
            ok "Installed $pkg."
        fi
    done
}

# ─── PYTHON VIRTUAL ENVIRONMENT ───────────────────────────────────────────────
setup_python_env() {
    local venv_dir="${APP_DIR}/venv"

    info "Setting up Python virtual environment..."

    if [[ ! -d "$venv_dir" ]]; then
        python3 -m venv "$venv_dir"
        ok "Created venv at $venv_dir."
    else
        ok "Venv already exists."
    fi

    "${venv_dir}/bin/pip" install --quiet --upgrade pip

    local py_pkgs=(flask flask-socketio eventlet psutil gunicorn)
    for pkg in "${py_pkgs[@]}"; do
        "${venv_dir}/bin/pip" install --quiet "$pkg"
        ok "Python package installed: $pkg"
    done
}

# ─── SYSTEM USER ──────────────────────────────────────────────────────────────
create_app_user() {
    if id "$APP_USER" &>/dev/null; then
        ok "System user '$APP_USER' already exists."
        # Ensure user is in its own group (in case primary group differs)
        if ! groups "$APP_USER" | grep -q "\b${APP_USER}\b"; then
            usermod -a -G "$APP_USER" "$APP_USER"
            ok "Added $APP_USER to group $APP_USER (supplementary)."
        fi
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "MG Travel service account" "$APP_USER"
        ok "Created system user '$APP_USER'."
    fi

    usermod -aG disk "$APP_USER" 2>/dev/null || true
}

# ─── DIRECTORY STRUCTURE ──────────────────────────────────────────────────────
create_directories() {
    info "Creating application directory structure..."

    ensure_dir "${APP_DIR}"                      "root:${APP_USER}"        "750"
    ensure_dir "${APP_DIR}/templates"            "root:${APP_USER}"        "750"
    ensure_dir "${APP_DIR}/static"               "root:${APP_USER}"        "750"
    ensure_dir "${APP_DIR}/static/css"           "root:${APP_USER}"        "750"
    ensure_dir "${APP_DIR}/static/js"            "root:${APP_USER}"        "750"
    ensure_dir "${APP_DIR}/backups"              "${APP_USER}:${APP_USER}" "750"
    ensure_dir "${APP_DIR}/logs"                 "${APP_USER}:${APP_USER}" "750"
    ensure_dir "/var/log/mgtravel"               "${APP_USER}:adm"         "750"

    ok "Directory structure created."
}

# ─── APPLICATION FILES ────────────────────────────────────────────────────────
write_app_files() {
    info "Writing application source files..."

    # ── app.py ────────────────────────────────────────────────────────────────
    cat > "${APP_DIR}/app.py" << 'PYEOF'
import os
import json
import subprocess
import threading
import psutil
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from device_manager import DeviceManager
from backup_engine import BackupEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

device_mgr = DeviceManager()
backup_eng = BackupEngine(socketio, backup_dir='/opt/mgtravel/backups')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify(backup_eng.get_status())

@app.route('/api/devices')
def api_devices():
    return jsonify(device_mgr.list_sd_devices())

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json(silent=True) or {}
    device = data.get('device')
    delete_mode = data.get('delete', False)
    auto_shutdown = data.get('auto_shutdown', False)
    if not device:
        return jsonify({'error': 'No device specified'}), 400
    if backup_eng.is_running():
        return jsonify({'error': 'Backup already running'}), 409
    t = threading.Thread(
        target=backup_eng.run_backup,
        args=(device, delete_mode, auto_shutdown),
        daemon=True
    )
    t.start()
    return jsonify({'started': True})

@app.route('/api/eject', methods=['POST'])
def api_eject():
    data = request.get_json(silent=True) or {}
    device = data.get('device')
    if not device:
        return jsonify({'error': 'No device specified'}), 400
    result = device_mgr.safe_eject(device)
    return jsonify(result)

@app.route('/api/health')
def api_health():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/opt/mgtravel/backups')
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        if 'cpu_thermal' in temps:
            temp = temps['cpu_thermal'][0].current
    except Exception:
        pass
    return jsonify({
        'cpu_percent': cpu,
        'mem_total_mb': round(mem.total / 1024 / 1024, 1),
        'mem_used_mb': round(mem.used / 1024 / 1024, 1),
        'mem_percent': mem.percent,
        'disk_total_gb': round(disk.total / 1024 / 1024 / 1024, 2),
        'disk_used_gb': round(disk.used / 1024 / 1024 / 1024, 2),
        'disk_free_gb': round(disk.free / 1024 / 1024 / 1024, 2),
        'disk_percent': disk.percent,
        'cpu_temp_c': temp,
    })

@socketio.on('connect')
def on_connect():
    emit('status', backup_eng.get_status())

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000)
PYEOF

    # ── device_manager.py ─────────────────────────────────────────────────────
    cat > "${APP_DIR}/device_manager.py" << 'PYEOF'
import os
import re
import subprocess
import json

class DeviceManager:

    def list_sd_devices(self):
        devices = []
        try:
            result = subprocess.run(
                ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,LABEL,MODEL,HOTPLUG,RM'],
                capture_output=True, text=True, timeout=10
            )
            data = json.loads(result.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') == 'disk' and (dev.get('hotplug') == '1' or dev.get('rm') == '1'):
                    entry = {
                        'device': f"/dev/{dev['name']}",
                        'name': dev.get('name'),
                        'size': dev.get('size'),
                        'label': dev.get('label') or dev.get('model') or dev['name'],
                        'mountpoint': None,
                        'partitions': []
                    }
                    for child in dev.get('children', []):
                        part = {
                            'device': f"/dev/{child['name']}",
                            'mountpoint': child.get('mountpoint'),
                            'label': child.get('label') or '',
                            'size': child.get('size'),
                        }
                        entry['partitions'].append(part)
                        if child.get('mountpoint'):
                            entry['mountpoint'] = child['mountpoint']
                    devices.append(entry)
        except Exception:
            pass
        return devices

    def safe_eject(self, device):
        try:
            subprocess.run(['sync'], timeout=30)
            result = subprocess.run(
                ['lsblk', '-J', '-o', 'NAME,MOUNTPOINT', device],
                capture_output=True, text=True, timeout=10
            )
            data = json.loads(result.stdout)
            for dev in data.get('blockdevices', []):
                for child in dev.get('children', []):
                    mp = child.get('mountpoint')
                    if mp:
                        subprocess.run(['sudo', 'umount', '-l', f"/dev/{child['name']}"],
                                       capture_output=True, timeout=30)
                if dev.get('mountpoint'):
                    subprocess.run(['sudo', 'umount', '-l', device],
                                   capture_output=True, timeout=30)
            subprocess.run(['sync'], timeout=10)
            return {'ejected': True, 'device': device}
        except Exception as e:
            return {'ejected': False, 'error': str(e)}

    def mount_readonly(self, partition):
        mp = '/mnt/mgtravel_src'
        os.makedirs(mp, exist_ok=True)
        subprocess.run(
            ['sudo', 'mount', '-o', 'ro', partition, mp],
            check=True, timeout=30
        )
        return mp

    def unmount(self, mountpoint):
        try:
            subprocess.run(['sync'], timeout=30)
            subprocess.run(['sudo', 'umount', '-l', mountpoint],
                           capture_output=True, timeout=30)
        except Exception:
            pass
PYEOF

    # ── backup_engine.py ──────────────────────────────────────────────────────
    cat > "${APP_DIR}/backup_engine.py" << 'PYEOF'
import os
import re
import shutil
import subprocess
import threading
import time
import datetime
import psutil
import json

class BackupEngine:

    def __init__(self, socketio, backup_dir):
        self.socketio = socketio
        self.backup_dir = backup_dir
        self._lock = threading.Lock()
        self._status = {
            'state': 'idle',
            'device': None,
            'progress': 0,
            'speed': '',
            'eta': '',
            'files': '',
            'message': 'Ready',
            'backup_name': None,
            'error': None,
        }

    def get_status(self):
        with self._lock:
            return dict(self._status)

    def is_running(self):
        with self._lock:
            return self._status['state'] in ('copying', 'verifying', 'finishing')

    def _set(self, **kwargs):
        with self._lock:
            self._status.update(kwargs)
        self.socketio.emit('status', self.get_status())

    def _abort(self, message):
        self._set(state='error', message=message, error=message, progress=0)

    def run_backup(self, device, delete_mode=False, auto_shutdown=False):
        from device_manager import DeviceManager
        dm = DeviceManager()

        self._set(state='copying', device=device, progress=0,
                  message='Detecting device...', error=None)

        try:
            devices = dm.list_sd_devices()
            target_dev = None
            for d in devices:
                if d['device'] == device:
                    target_dev = d
                    break

            if not target_dev:
                return self._abort(f"Device {device} not found.")

            if target_dev['partitions']:
                partition = target_dev['partitions'][0]['device']
                label = (target_dev['partitions'][0]['label'] or
                         target_dev['label'] or
                         os.path.basename(device))
            else:
                partition = device
                label = target_dev['label'] or os.path.basename(device)

            label = re.sub(r'[^\w\-_.]', '_', label.strip()) or 'sd_backup'
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{label}_{timestamp}"
            dest_final = os.path.join(self.backup_dir, backup_name)
            dest_temp  = dest_final + '.tmp'

            src_size = self._get_partition_used(partition)
            disk = psutil.disk_usage(self.backup_dir)
            if src_size > 0 and disk.free < src_size * 1.05:
                return self._abort(
                    f"Insufficient space. Need {src_size // 1024 // 1024} MB, "
                    f"have {disk.free // 1024 // 1024} MB free."
                )

            self._set(message='Mounting source read-only...')
            src_mp = '/mnt/mgtravel_src'
            os.makedirs(src_mp, exist_ok=True)

            subprocess.run(['sudo', 'umount', '-l', src_mp], capture_output=True)
            subprocess.run(['sudo', 'mount', '-o', 'ro', partition, src_mp],
                           check=True, timeout=30)

            os.makedirs(dest_temp, exist_ok=True)
            self._set(backup_name=backup_name, message='Starting rsync...')

            rsync_cmd = [
                'rsync', '-a',
                '--info=progress2',
                '--partial',
                '--partial-dir=.rsync-partial',
                '--human-readable',
                '--no-inc-recursive',
            ]
            if delete_mode:
                rsync_cmd.append('--delete')

            rsync_cmd += [src_mp + '/', dest_temp + '/']

            success = self._run_rsync(rsync_cmd, partition, src_mp)

            if not success:
                shutil.rmtree(dest_temp, ignore_errors=True)
                subprocess.run(['sudo', 'umount', '-l', src_mp], capture_output=True)
                return self._abort('rsync failed. Temp folder discarded.')

            self._set(state='verifying', message='Verifying backup integrity...')
            if not self._verify(src_mp, dest_temp):
                shutil.rmtree(dest_temp, ignore_errors=True)
                subprocess.run(['sudo', 'umount', '-l', src_mp], capture_output=True)
                return self._abort('Verification failed. Temp folder discarded.')

            self._set(state='finishing', message='Finalising backup...')
            os.rename(dest_temp, dest_final)
            subprocess.run(['sync'], timeout=60)

            subprocess.run(['sudo', 'umount', '-l', src_mp], capture_output=True)
            subprocess.run(['sync'], timeout=10)

            self._set(state='done', progress=100,
                      message=f'Backup complete: {backup_name}',
                      speed='', eta='')

            self._cleanup_old_temps()

            if auto_shutdown:
                time.sleep(5)
                subprocess.run(['sudo', 'shutdown', '-h', 'now'])

        except Exception as e:
            subprocess.run(['sudo', 'umount', '-l', '/mnt/mgtravel_src'],
                           capture_output=True)
            self._abort(f'Unexpected error: {str(e)}')

    def _run_rsync(self, cmd, partition, src_mp):
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True
            )
            pattern = re.compile(
                r'(\d[\d,]*)\s+([\d.]+%)\s+([\d.]+\s*\w+/s)\s+([\d:]+|\-:--:--)'
            )
            files_pattern = re.compile(r'(\d[\d,]*)\s+files')
            for line in proc.stdout:
                line = line.strip()
                m = pattern.search(line)
                if m:
                    pct = float(m.group(2).rstrip('%'))
                    self._set(
                        progress=round(pct, 1),
                        speed=m.group(3),
                        eta=m.group(4),
                    )
                mf = files_pattern.search(line)
                if mf:
                    self._set(files=mf.group(1))
                if not os.path.exists(partition):
                    proc.terminate()
                    return False

            proc.wait(timeout=600)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            proc.kill()
            return False
        except Exception:
            return False

    def _verify(self, src, dst):
        try:
            result = subprocess.run(
                ['rsync', '-a', '--checksum', '--dry-run',
                 '--itemize-changes', src + '/', dst + '/'],
                capture_output=True, text=True, timeout=300
            )
            changes = [l for l in result.stdout.splitlines()
                       if l and not l.startswith('.')]
            return len(changes) == 0
        except Exception:
            return False

    def _get_partition_used(self, partition):
        try:
            mp = '/mnt/mgtravel_probe'
            os.makedirs(mp, exist_ok=True)
            subprocess.run(['sudo', 'mount', '-o', 'ro', partition, mp],
                           capture_output=True, timeout=15)
            usage = psutil.disk_usage(mp)
            subprocess.run(['sudo', 'umount', '-l', mp], capture_output=True)
            return usage.used
        except Exception:
            return 0

    def _cleanup_old_temps(self):
        import glob
        now = time.time()
        for d in glob.glob(os.path.join(self.backup_dir, '*.tmp')):
            if os.path.isdir(d):
                age = now - os.path.getmtime(d)
                if age > 86400 * 7:
                    shutil.rmtree(d, ignore_errors=True)
PYEOF

    # ── verifier.py ───────────────────────────────────────────────────────────
    cat > "${APP_DIR}/verifier.py" << 'PYEOF'
import os
import subprocess

def verify_backup(src_path, dst_path):
    if not os.path.isdir(src_path):
        return False, f"Source path not found: {src_path}"
    if not os.path.isdir(dst_path):
        return False, f"Destination path not found: {dst_path}"
    try:
        result = subprocess.run(
            ['rsync', '-a', '--checksum', '--dry-run',
             '--itemize-changes', src_path + '/', dst_path + '/'],
            capture_output=True, text=True, timeout=300
        )
        changes = [l for l in result.stdout.splitlines() if l and not l.startswith('.')]
        if changes:
            return False, f"{len(changes)} differences found."
        return True, "Verification passed."
    except Exception as e:
        return False, str(e)
PYEOF

    # ── templates/index.html ──────────────────────────────────────────────────
    cat > "${APP_DIR}/templates/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MG Travel — SD Backup Station</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="/static/css/style.css"/>
</head>
<body>
<div class="bg-mesh"></div>
<div class="app">

  <!-- ── Sidebar ─────────────────────────────────────────────────────────── -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-logo">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
          <path d="M2 17l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
          <path d="M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="brand-text">
        <span class="brand-name">MG Servers</span>
        <span class="brand-sub">MG Travel</span>
      </div>
    </div>

    <nav class="nav">
      <a class="nav-item active" data-view="backup">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        Backup
      </a>
      <a class="nav-item" data-view="health">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
        System
      </a>
    </nav>

    <div class="sidebar-status">
      <div class="status-dot-wrap">
        <span class="status-dot" id="conn-dot"></span>
        <span class="status-dot-label" id="conn-label">Connecting</span>
      </div>
      <div class="hostname-tag">mgtravel.local</div>
    </div>
  </aside>

  <!-- ── Main content ─────────────────────────────────────────────────────── -->
  <main class="main">

    <!-- Backup View -->
    <div class="view active" id="view-backup">
      <div class="page-header">
        <div>
          <h1>SD Backup</h1>
          <p class="page-sub">Insert an SD card to begin</p>
        </div>
        <div id="state-badge" class="badge badge-idle">
          <span class="badge-dot"></span>
          <span id="state-label">Idle</span>
        </div>
      </div>

      <!-- Device selector -->
      <div class="section-label">STORAGE DEVICE</div>
      <div id="device-list" class="device-list">
        <div class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <rect x="2" y="6" width="20" height="12" rx="2"/>
              <circle cx="12" cy="12" r="2"/>
            </svg>
          </div>
          <p>Scanning for SD cards…</p>
        </div>
      </div>

      <!-- Options -->
      <div id="device-options" class="options-panel" style="display:none">
        <div class="section-label">OPTIONS</div>
        <div class="options-grid">
          <label class="option-card">
            <div class="option-info">
              <span class="option-title">Delete Mode</span>
              <span class="option-desc">Mirror deletions from source</span>
            </div>
            <div class="toggle-wrap">
              <input type="checkbox" id="opt-delete" class="toggle-input"/>
              <span class="toggle-track"><span class="toggle-thumb"></span></span>
            </div>
          </label>
          <label class="option-card">
            <div class="option-info">
              <span class="option-title">Auto Shutdown</span>
              <span class="option-desc">Power off after completion</span>
            </div>
            <div class="toggle-wrap">
              <input type="checkbox" id="opt-shutdown" class="toggle-input"/>
              <span class="toggle-track"><span class="toggle-thumb"></span></span>
            </div>
          </label>
        </div>
      </div>

      <!-- Progress panel -->
      <div id="progress-panel" class="progress-panel" style="display:none">
        <div class="section-label">PROGRESS</div>
        <div class="progress-card">
          <div class="progress-header">
            <span id="progress-label">Copying files…</span>
            <span id="progress-pct" class="progress-pct">0%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" id="progress-fill"></div>
          </div>
          <div class="progress-meta">
            <div class="meta-item">
              <span class="meta-label">Speed</span>
              <span class="meta-val" id="meta-speed">—</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">ETA</span>
              <span class="meta-val" id="meta-eta">—</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">Files</span>
              <span class="meta-val" id="meta-files">—</span>
            </div>
          </div>
        </div>
        <p id="status-msg" class="status-msg"></p>
      </div>

      <!-- Actions -->
      <div class="action-row">
        <button id="btn-start" class="btn btn-primary" disabled>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          Start Backup
        </button>
        <button id="btn-eject" class="btn btn-ghost" disabled>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <polyline points="23 7 13 7 13 17"/>
            <path d="M1 21 13 7"/>
            <polyline points="1 7 11 7"/>
          </svg>
          Safe Eject
        </button>
      </div>
    </div>

    <!-- Health View -->
    <div class="view" id="view-health">
      <div class="page-header">
        <div>
          <h1>System Health</h1>
          <p class="page-sub">Live diagnostics — Pi Zero 2W</p>
        </div>
      </div>

      <div class="health-grid">
        <div class="health-card">
          <div class="health-icon health-icon-blue">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="4" y="4" width="16" height="16" rx="2"/>
              <rect x="9" y="9" width="16" height="16"/>
              <line x1="9" y1="1" x2="9" y2="4"/>
              <line x1="15" y1="1" x2="15" y2="4"/>
              <line x1="9" y1="20" x2="9" y2="23"/>
              <line x1="15" y1="20" x2="15" y2="23"/>
              <line x1="20" y1="9" x2="23" y2="9"/>
              <line x1="20" y1="14" x2="23" y2="14"/>
              <line x1="1" y1="9" x2="4" y2="9"/>
              <line x1="1" y1="14" x2="4" y2="14"/>
            </svg>
          </div>
          <div class="health-body">
            <span class="health-label">CPU Usage</span>
            <span class="health-val" id="h-cpu">—</span>
          </div>
          <div class="health-bar-wrap"><div class="health-bar" id="hb-cpu"></div></div>
        </div>

        <div class="health-card">
          <div class="health-icon health-icon-purple">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <ellipse cx="12" cy="5" rx="9" ry="3"/>
              <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
              <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
            </svg>
          </div>
          <div class="health-body">
            <span class="health-label">RAM Usage</span>
            <span class="health-val" id="h-mem">—</span>
          </div>
          <div class="health-bar-wrap"><div class="health-bar" id="hb-mem"></div></div>
        </div>

        <div class="health-card">
          <div class="health-icon health-icon-cyan">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <div class="health-body">
            <span class="health-label">Disk Free</span>
            <span class="health-val" id="h-disk">—</span>
          </div>
          <div class="health-bar-wrap"><div class="health-bar" id="hb-disk"></div></div>
        </div>

        <div class="health-card">
          <div class="health-icon health-icon-orange">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/>
            </svg>
          </div>
          <div class="health-body">
            <span class="health-label">CPU Temp</span>
            <span class="health-val" id="h-temp">—</span>
          </div>
          <div class="health-bar-wrap"><div class="health-bar health-bar-temp" id="hb-temp"></div></div>
        </div>
      </div>

      <div class="section-label" style="margin-top:24px">RECENT BACKUPS</div>
      <div id="backup-list" class="backup-list">
        <p class="muted-msg">Loading…</p>
      </div>
    </div>

  </main>
</div>

<script src="/static/js/socket.io.min.js"></script>
<script src="/static/js/app.js"></script>
</body>
</html>
HTMLEOF

    # ── static/css/style.css ──────────────────────────────────────────────────
    cat > "${APP_DIR}/static/css/style.css" << 'CSSEOF'
/* ─── Reset & Base ─────────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:         #07090f;
  --bg2:        #0c0e17;
  --surface:    #111422;
  --surface2:   #171a2d;
  --border:     rgba(255,255,255,0.07);
  --border2:    rgba(255,255,255,0.12);

  --blue:       #3b82f6;
  --blue-dim:   rgba(59,130,246,0.15);
  --blue-glow:  rgba(59,130,246,0.35);
  --purple:     #8b5cf6;
  --purple-dim: rgba(139,92,246,0.15);
  --cyan:       #06b6d4;
  --cyan-dim:   rgba(6,182,212,0.15);
  --orange:     #f97316;
  --orange-dim: rgba(249,115,22,0.15);
  --green:      #22c55e;
  --green-dim:  rgba(34,197,94,0.12);
  --red:        #ef4444;
  --red-dim:    rgba(239,68,68,0.12);
  --amber:      #f59e0b;
  --amber-dim:  rgba(245,158,11,0.12);

  --text:       #e2e8f0;
  --text2:      #94a3b8;
  --text3:      #475569;

  --sidebar-w:  220px;
  --radius:     14px;
  --radius-sm:  8px;
  --font:       'Inter', system-ui, -apple-system, sans-serif;
}

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

/* ─── Background mesh ──────────────────────────────────────────────────────── */
.bg-mesh {
  position: fixed;
  inset: 0;
  z-index: 0;
  background:
    radial-gradient(ellipse 80% 60% at 10% 0%, rgba(59,130,246,0.07) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 90% 100%, rgba(139,92,246,0.06) 0%, transparent 60%);
  pointer-events: none;
}

/* ─── App shell ────────────────────────────────────────────────────────────── */
.app {
  position: relative;
  z-index: 1;
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* ─── Sidebar ──────────────────────────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w);
  flex-shrink: 0;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 20px 12px;
  gap: 32px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 8px;
}

.brand-logo {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, var(--blue) 0%, var(--purple) 100%);
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  color: #fff;
  flex-shrink: 0;
  box-shadow: 0 4px 16px rgba(59,130,246,0.3);
}

.brand-text { display: flex; flex-direction: column; }
.brand-name {
  font-size: 13px;
  font-weight: 700;
  color: var(--text);
  letter-spacing: 0.01em;
  line-height: 1.2;
}
.brand-sub {
  font-size: 11px;
  color: var(--text3);
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: 9px;
  color: var(--text2);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  text-decoration: none;
  user-select: none;
}
.nav-item:hover { background: rgba(255,255,255,0.05); color: var(--text); }
.nav-item.active {
  background: var(--blue-dim);
  color: var(--blue);
  border: 1px solid rgba(59,130,246,0.2);
}
.nav-item svg { flex-shrink: 0; }

.sidebar-status {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  background: var(--surface);
  border-radius: 10px;
  border: 1px solid var(--border);
}

.status-dot-wrap {
  display: flex;
  align-items: center;
  gap: 7px;
}

.status-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--text3);
  flex-shrink: 0;
  transition: background 0.3s;
}
.status-dot.connected { background: var(--green); box-shadow: 0 0 6px var(--green); }
.status-dot.error     { background: var(--red); }

.status-dot-label { font-size: 12px; color: var(--text2); }

.hostname-tag {
  font-size: 11px;
  color: var(--text3);
  font-family: 'SF Mono', 'Fira Code', monospace;
  letter-spacing: 0.02em;
}

/* ─── Main ─────────────────────────────────────────────────────────────────── */
.main {
  flex: 1;
  overflow-y: auto;
  padding: 32px 36px;
  scrollbar-width: thin;
  scrollbar-color: var(--border2) transparent;
}

.view { display: none; }
.view.active { display: block; }

/* ─── Page header ──────────────────────────────────────────────────────────── */
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 28px;
}
.page-header h1 {
  font-size: 22px;
  font-weight: 700;
  color: var(--text);
  line-height: 1.2;
}
.page-sub { font-size: 13px; color: var(--text3); margin-top: 3px; }

/* ─── Badge ────────────────────────────────────────────────────────────────── */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 99px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  border: 1px solid transparent;
}
.badge-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
}
.badge-idle      { background: var(--surface2); color: var(--text3); border-color: var(--border); }
.badge-idle .badge-dot { background: var(--text3); }
.badge-copying   { background: var(--blue-dim); color: var(--blue); border-color: rgba(59,130,246,0.3); }
.badge-copying .badge-dot { background: var(--blue); animation: pulse-dot 1.2s infinite; }
.badge-verifying { background: var(--purple-dim); color: var(--purple); border-color: rgba(139,92,246,0.3); }
.badge-verifying .badge-dot { background: var(--purple); animation: pulse-dot 1.2s infinite; }
.badge-finishing { background: var(--amber-dim); color: var(--amber); border-color: rgba(245,158,11,0.3); }
.badge-finishing .badge-dot { background: var(--amber); animation: pulse-dot 1.2s infinite; }
.badge-done      { background: var(--green-dim); color: var(--green); border-color: rgba(34,197,94,0.3); }
.badge-done .badge-dot { background: var(--green); }
.badge-error     { background: var(--red-dim); color: var(--red); border-color: rgba(239,68,68,0.3); }
.badge-error .badge-dot { background: var(--red); }

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.5; transform: scale(0.8); }
}

/* ─── Section label ─────────────────────────────────────────────────────────── */
.section-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.1em;
  color: var(--text3);
  text-transform: uppercase;
  margin-bottom: 10px;
}

/* ─── Device list ──────────────────────────────────────────────────────────── */
.device-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 24px;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 40px 20px;
  background: var(--surface);
  border: 1px dashed var(--border2);
  border-radius: var(--radius);
  color: var(--text3);
  text-align: center;
  font-size: 13px;
}
.empty-icon {
  width: 52px; height: 52px;
  background: var(--surface2);
  border-radius: 14px;
  display: flex; align-items: center; justify-content: center;
  color: var(--text3);
}

.device-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  transition: all 0.15s;
  position: relative;
  overflow: hidden;
}
.device-card::before {
  content: '';
  position: absolute;
  inset: 0;
  opacity: 0;
  background: linear-gradient(90deg, var(--blue-dim), transparent);
  transition: opacity 0.2s;
  pointer-events: none;
}
.device-card:hover { border-color: var(--border2); transform: translateY(-1px); }
.device-card:hover::before { opacity: 0.5; }
.device-card.selected { border-color: var(--blue); box-shadow: 0 0 0 1px var(--blue), 0 4px 20px rgba(59,130,246,0.15); }
.device-card.selected::before { opacity: 1; }

.device-icon {
  width: 40px; height: 40px;
  background: var(--blue-dim);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  color: var(--blue);
  flex-shrink: 0;
}

.device-body { flex: 1; min-width: 0; }
.device-name { font-weight: 600; font-size: 14px; color: var(--text); }
.device-path { font-size: 12px; color: var(--text3); margin-top: 2px; font-family: monospace; }

.device-size {
  font-size: 12px;
  font-weight: 600;
  color: var(--text2);
  background: var(--surface2);
  border: 1px solid var(--border);
  padding: 3px 9px;
  border-radius: 6px;
}

.device-check {
  width: 20px; height: 20px;
  background: var(--blue);
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  opacity: 0;
  transform: scale(0.7);
  transition: all 0.2s;
}
.device-card.selected .device-check { opacity: 1; transform: scale(1); }

/* ─── Options ──────────────────────────────────────────────────────────────── */
.options-panel { margin-bottom: 24px; }
.options-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }

.option-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: border-color 0.15s;
  user-select: none;
}
.option-card:hover { border-color: var(--border2); }

.option-info { display: flex; flex-direction: column; gap: 2px; }
.option-title { font-size: 13px; font-weight: 600; color: var(--text); }
.option-desc  { font-size: 12px; color: var(--text3); }

.toggle-wrap { flex-shrink: 0; }
.toggle-input { display: none; }
.toggle-track {
  display: block;
  width: 40px; height: 22px;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 99px;
  position: relative;
  cursor: pointer;
  transition: background 0.2s, border-color 0.2s;
}
.toggle-thumb {
  position: absolute;
  top: 2px; left: 2px;
  width: 16px; height: 16px;
  background: var(--text3);
  border-radius: 50%;
  transition: transform 0.2s, background 0.2s;
}
.toggle-input:checked + .toggle-track { background: var(--blue); border-color: var(--blue); }
.toggle-input:checked + .toggle-track .toggle-thumb { transform: translateX(18px); background: #fff; }

/* ─── Progress ─────────────────────────────────────────────────────────────── */
.progress-panel { margin-bottom: 28px; }

.progress-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.progress-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  font-weight: 500;
  color: var(--text2);
}
.progress-pct { font-weight: 700; color: var(--text); font-size: 15px; }

.progress-track {
  height: 6px;
  background: var(--surface2);
  border-radius: 99px;
  overflow: hidden;
  position: relative;
}
.progress-fill {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--blue) 0%, var(--purple) 100%);
  border-radius: 99px;
  transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}
.progress-fill::after {
  content: '';
  position: absolute;
  top: 0; left: -100%;
  width: 100%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
  animation: shimmer 2s infinite;
}
@keyframes shimmer {
  0% { left: -100%; }
  100% { left: 100%; }
}

.progress-meta {
  display: flex;
  gap: 24px;
}
.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label { font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.06em; }
.meta-val { font-size: 14px; font-weight: 600; color: var(--text); }

.status-msg {
  font-size: 12px;
  color: var(--text3);
  padding: 0 2px;
  min-height: 18px;
}

/* ─── Action row ───────────────────────────────────────────────────────────── */
.action-row {
  display: flex;
  gap: 10px;
}

.btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 10px;
  font-family: var(--font);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.btn:disabled { opacity: 0.35; cursor: not-allowed; pointer-events: none; }
.btn:active { transform: scale(0.97); }

.btn-primary {
  flex: 1;
  background: linear-gradient(135deg, var(--blue), #2563eb);
  color: #fff;
  box-shadow: 0 4px 14px rgba(59,130,246,0.35);
}
.btn-primary:hover:not(:disabled) {
  box-shadow: 0 6px 20px rgba(59,130,246,0.5);
  transform: translateY(-1px);
}

.btn-ghost {
  background: var(--surface);
  color: var(--text2);
  border: 1px solid var(--border2);
}
.btn-ghost:hover:not(:disabled) { background: var(--surface2); color: var(--text); }

/* ─── Health ───────────────────────────────────────────────────────────────── */
.health-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.health-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.health-icon {
  width: 38px; height: 38px;
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
}
.health-icon-blue   { background: var(--blue-dim);   color: var(--blue);   border: 1px solid rgba(59,130,246,0.2); }
.health-icon-purple { background: var(--purple-dim); color: var(--purple); border: 1px solid rgba(139,92,246,0.2); }
.health-icon-cyan   { background: var(--cyan-dim);   color: var(--cyan);   border: 1px solid rgba(6,182,212,0.2); }
.health-icon-orange { background: var(--orange-dim); color: var(--orange); border: 1px solid rgba(249,115,22,0.2); }

.health-body { display: flex; flex-direction: column; gap: 2px; }
.health-label { font-size: 12px; color: var(--text3); font-weight: 500; }
.health-val   { font-size: 20px; font-weight: 700; color: var(--text); line-height: 1.2; }

.health-bar-wrap {
  height: 4px;
  background: var(--surface2);
  border-radius: 99px;
  overflow: hidden;
}
.health-bar {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--blue), var(--purple));
  border-radius: 99px;
  transition: width 0.6s ease;
}
.health-bar-temp { background: linear-gradient(90deg, var(--cyan), var(--orange)); }

/* ─── Backup list ──────────────────────────────────────────────────────────── */
.backup-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.backup-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 13px;
}
.backup-item-name { font-weight: 500; color: var(--text); font-family: monospace; font-size: 12px; }
.backup-item-time { color: var(--text3); font-size: 12px; }

.muted-msg { color: var(--text3); font-size: 13px; padding: 8px 0; }

/* ─── Scrollbar ────────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 99px; }

/* ─── Responsive ───────────────────────────────────────────────────────────── */
@media (max-width: 680px) {
  :root { --sidebar-w: 64px; }
  .brand-text, .nav-item span, .status-dot-label, .hostname-tag { display: none; }
  .sidebar { padding: 16px 8px; align-items: center; }
  .brand { justify-content: center; padding: 4px; }
  .nav-item { justify-content: center; padding: 10px; }
  .main { padding: 20px 16px; }
  .health-grid { grid-template-columns: 1fr; }
  .options-grid { grid-template-columns: 1fr; }
  .action-row { flex-direction: column; }
  .progress-meta { flex-wrap: wrap; gap: 12px; }
}
CSSEOF

    # ── static/js/app.js ──────────────────────────────────────────────────────
    cat > "${APP_DIR}/static/js/app.js" << 'JSEOF'
(function () {
  'use strict';

  // ── Socket ──────────────────────────────────────────────────────────────────
  const socket = io({ transports: ['websocket'] });

  // ── State ───────────────────────────────────────────────────────────────────
  let selectedDevice = null;
  let currentState   = 'idle';

  // ── DOM ─────────────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const deviceList   = $('device-list');
  const deviceOpts   = $('device-options');
  const progressPnl  = $('progress-panel');
  const progressFill = $('progress-fill');
  const progressLbl  = $('progress-label');
  const progressPct  = $('progress-pct');
  const stateBadge   = $('state-badge');
  const stateLabel   = $('state-label');
  const statusMsg    = $('status-msg');
  const metaSpeed    = $('meta-speed');
  const metaEta      = $('meta-eta');
  const metaFiles    = $('meta-files');
  const btnStart     = $('btn-start');
  const btnEject     = $('btn-eject');
  const optDelete    = $('opt-delete');
  const optShutdown  = $('opt-shutdown');
  const connDot      = $('conn-dot');
  const connLabel    = $('conn-label');

  // ── Navigation ──────────────────────────────────────────────────────────────
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      item.classList.add('active');
      const view = item.dataset.view;
      $('view-' + view).classList.add('active');
      if (view === 'health') fetchHealth();
    });
  });

  // ── Connection status ────────────────────────────────────────────────────────
  socket.on('connect', () => {
    connDot.className = 'status-dot connected';
    connLabel.textContent = 'Connected';
    fetch('/api/status').then(r => r.json()).then(applyStatus).catch(() => {});
  });
  socket.on('disconnect', () => {
    connDot.className = 'status-dot error';
    connLabel.textContent = 'Disconnected';
  });

  // ── Status ───────────────────────────────────────────────────────────────────
  const STATE_MAP = {
    idle:      { label: 'Idle',      msg: 'Ready' },
    copying:   { label: 'Copying',   msg: 'Copying files…' },
    verifying: { label: 'Verifying', msg: 'Verifying integrity…' },
    finishing: { label: 'Finishing', msg: 'Finalising…' },
    done:      { label: 'Done',      msg: 'Backup complete' },
    error:     { label: 'Error',     msg: '' },
  };

  function applyStatus(data) {
    currentState = data.state || 'idle';
    const info = STATE_MAP[currentState] || STATE_MAP.idle;

    stateLabel.textContent = info.label;
    stateBadge.className   = 'badge badge-' + currentState;

    const labelText = data.message || info.msg;
    progressLbl.textContent = labelText;
    statusMsg.textContent   = labelText;

    const pct = Math.min(100, Math.max(0, parseFloat(data.progress) || 0));
    progressFill.style.width = pct + '%';
    progressPct.textContent  = pct.toFixed(1) + '%';

    if (data.speed) metaSpeed.textContent = data.speed;
    if (data.eta)   metaEta.textContent   = data.eta;
    if (data.files) metaFiles.textContent = data.files;

    const isActive = ['copying', 'verifying', 'finishing'].includes(currentState);
    const showProgress = isActive || currentState === 'done' || currentState === 'error';
    progressPnl.style.display = showProgress ? 'block' : 'none';

    btnStart.disabled = isActive || !selectedDevice;
    btnEject.disabled = isActive || !selectedDevice;
    btnStart.innerHTML = isActive
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="10 15 15 12 10 9 10 15"/></svg> Running…`
      : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> Start Backup`;

    if (currentState === 'done') {
      metaSpeed.textContent = '—';
      metaEta.textContent   = '—';
      progressFill.style.width = '100%';
    }
  }

  socket.on('status', applyStatus);

  // ── Device scan ──────────────────────────────────────────────────────────────
  function scanDevices() {
    fetch('/api/devices')
      .then(r => r.json())
      .then(renderDevices)
      .catch(() => {
        deviceList.innerHTML =
          '<div class="empty-state"><p style="color:var(--red)">Error scanning devices</p></div>';
      });
  }

  function renderDevices(devices) {
    if (!devices || devices.length === 0) {
      deviceList.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <rect x="2" y="6" width="20" height="12" rx="2"/>
              <circle cx="12" cy="12" r="2"/>
            </svg>
          </div>
          <p>No SD cards detected — insert a card</p>
        </div>`;
      deviceOpts.style.display = 'none';
      btnStart.disabled = true;
      btnEject.disabled = true;
      if (selectedDevice) {
        selectedDevice = null;
      }
      return;
    }

    let html = '';
    devices.forEach(d => {
      const sel = selectedDevice && selectedDevice.device === d.device ? 'selected' : '';
      const label = esc(d.label || d.name || d.device);
      const size  = esc(d.size || '?');
      const path  = esc(d.device);
      html += `
        <div class="device-card ${sel}" data-device='${JSON.stringify(d).replace(/'/g,"&#39;")}'>
          <div class="device-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="6" width="20" height="12" rx="2"/>
              <circle cx="12" cy="12" r="2"/>
              <path d="M6 6V4m4 2V4m4 2V4"/>
            </svg>
          </div>
          <div class="device-body">
            <div class="device-name">${label}</div>
            <div class="device-path">${path}</div>
          </div>
          <div class="device-size">${size}</div>
          <div class="device-check">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          </div>
        </div>`;
    });

    deviceList.innerHTML = html;

    document.querySelectorAll('.device-card').forEach(card => {
      card.addEventListener('click', () => {
        if (['copying','verifying','finishing'].includes(currentState)) return;
        selectedDevice = JSON.parse(card.dataset.device);
        document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        deviceOpts.style.display = 'block';
        btnStart.disabled = false;
        btnEject.disabled = false;
      });
    });

    // Revalidate selection
    if (selectedDevice) {
      const still = devices.find(d => d.device === selectedDevice.device);
      if (!still) {
        selectedDevice = null;
        deviceOpts.style.display = 'none';
        btnStart.disabled = true;
        btnEject.disabled = true;
      }
    }
  }

  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Start ────────────────────────────────────────────────────────────────────
  btnStart.addEventListener('click', () => {
    if (!selectedDevice) return;
    fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device: selectedDevice.device,
        delete: optDelete.checked,
        auto_shutdown: optShutdown.checked,
      })
    })
    .then(r => r.json())
    .then(d => {
      if (d.error) statusMsg.textContent = 'Error: ' + d.error;
    })
    .catch(() => { statusMsg.textContent = 'Failed to start backup.'; });
  });

  // ── Eject ────────────────────────────────────────────────────────────────────
  btnEject.addEventListener('click', () => {
    if (!selectedDevice) return;
    const orig = btnEject.innerHTML;
    btnEject.disabled = true;
    btnEject.innerHTML = 'Ejecting…';
    fetch('/api/eject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device: selectedDevice.device })
    })
    .then(r => r.json())
    .then(d => {
      if (d.ejected) {
        statusMsg.textContent = '✓ Device safely ejected. You may remove the card.';
        selectedDevice = null;
        btnStart.disabled = true;
        btnEject.innerHTML = orig;
        deviceOpts.style.display = 'none';
        scanDevices();
      } else {
        statusMsg.textContent = 'Eject error: ' + (d.error || 'unknown');
        btnEject.disabled = false;
        btnEject.innerHTML = orig;
      }
    })
    .catch(() => {
      statusMsg.textContent = 'Eject request failed.';
      btnEject.disabled = false;
      btnEject.innerHTML = orig;
    });
  });

  // ── Health ───────────────────────────────────────────────────────────────────
  function fetchHealth() {
    fetch('/api/health')
      .then(r => r.json())
      .then(d => {
        $('h-cpu').textContent  = (d.cpu_percent  || 0).toFixed(1) + '%';
        $('h-mem').textContent  = (d.mem_percent  || 0).toFixed(0) + '%';
        $('h-disk').textContent = (d.disk_free_gb || 0).toFixed(2) + ' GB';
        $('h-temp').textContent = d.cpu_temp_c ? d.cpu_temp_c.toFixed(1) + ' °C' : '—';

        const setBar = (id, val, max) => {
          const el = $(id);
          if (el) el.style.width = Math.min(100, (val / max) * 100).toFixed(1) + '%';
        };
        setBar('hb-cpu',  d.cpu_percent  || 0, 100);
        setBar('hb-mem',  d.mem_percent  || 0, 100);
        setBar('hb-disk', d.disk_percent || 0, 100);
        setBar('hb-temp', d.cpu_temp_c   || 0, 85);
      })
      .catch(() => {});
  }

  // ── Init ─────────────────────────────────────────────────────────────────────
  scanDevices();
  fetchHealth();
  setInterval(scanDevices, 8000);
  setInterval(fetchHealth, 6000);
})();
JSEOF

    # Download Socket.IO client JS
    info "Downloading Socket.IO client..."
    local sockio_url="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"
    local sockio_dst="${APP_DIR}/static/js/socket.io.min.js"
    if [[ ! -f "$sockio_dst" ]]; then
        curl -fsSL --retry 3 -o "$sockio_dst" "$sockio_url" \
            || warn "Could not download Socket.IO. Place socket.io.min.js at $sockio_dst manually."
    fi

    # Fix ownership
    chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}/backups" "${APP_DIR}/logs"
    chown -R "root:${APP_USER}"        "${APP_DIR}/app.py" \
                                        "${APP_DIR}/backup_engine.py" \
                                        "${APP_DIR}/device_manager.py" \
                                        "${APP_DIR}/verifier.py" \
                                        "${APP_DIR}/templates" \
                                        "${APP_DIR}/static" \
                                        "${APP_DIR}/venv" 2>/dev/null || true
    chmod 640 "${APP_DIR}/app.py" \
              "${APP_DIR}/backup_engine.py" \
              "${APP_DIR}/device_manager.py" \
              "${APP_DIR}/verifier.py"
    find "${APP_DIR}/templates" -type f -exec chmod 640 {} \;
    find "${APP_DIR}/static"    -type f -exec chmod 644 {} \;

    ok "Application files written."
}

# ─── UDEV RULES ───────────────────────────────────────────────────────────────
configure_udev() {
    info "Configuring udev rules for SD card detection..."
    cat > "$UDEV_RULE" << 'UDEVEOF'
# MG Travel — SD card event logging
ACTION=="add",    KERNEL=="sd[b-z]", SUBSYSTEM=="block", RUN+="/bin/logger -t mgtravel 'SD card inserted: %k'"
ACTION=="remove", KERNEL=="sd[b-z]", SUBSYSTEM=="block", RUN+="/bin/logger -t mgtravel 'SD card removed: %k'"
UDEVEOF
    udevadm control --reload-rules 2>/dev/null || true
    ok "Udev rules configured."
}

# ─── SYSTEMD SERVICE ──────────────────────────────────────────────────────────
configure_systemd_service() {
    info "Configuring systemd service..."
    backup_file "$SERVICE_FILE"

    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=MG Travel — SD Backup Station (MG Servers)
Documentation=https://mgservers.io
After=network.target
Wants=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=FLASK_ENV=production
ExecStart=${APP_DIR}/venv/bin/python3 -m gunicorn \
    --worker-class eventlet \
    --workers 2 \
    --bind 127.0.0.1:${APP_PORT} \
    --timeout 120 \
    --keep-alive 5 \
    --max-requests 500 \
    --max-requests-jitter 50 \
    --log-level warning \
    --access-logfile /var/log/mgtravel/access.log \
    --error-logfile  /var/log/mgtravel/error.log \
    app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5


StandardOutput=journal
StandardError=journal
SyslogIdentifier=mgtravel

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable mgtravel.service
    ok "Systemd service configured and enabled."
}

# ─── NGINX ────────────────────────────────────────────────────────────────────
configure_nginx() {
    info "Configuring nginx reverse proxy..."
    backup_file "$NGINX_CONF"
    backup_file "/etc/nginx/nginx.conf"

    if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
        sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf || true
        if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
            sed -i '/http {/a \    server_tokens off;' /etc/nginx/nginx.conf
        fi
    fi

    cat > "$NGINX_CONF" << 'NGINXEOF'
limit_req_zone $binary_remote_addr zone=mgtravel:10m rate=20r/s;

server {
    listen 80 default_server;
    server_name _;

    access_log /var/log/nginx/mgtravel_access.log;
    error_log  /var/log/nginx/mgtravel_error.log warn;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml;
    gzip_min_length 1024;
    gzip_vary on;

    client_max_body_size 1m;
    client_body_timeout 30s;
    client_header_timeout 30s;
    send_timeout 30s;

    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "no-referrer-when-downgrade";

    location / {
        limit_req zone=mgtravel burst=40 nodelay;
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering    off;
    }

    location /static/ {
        alias /opt/mgtravel/static/;
        expires 1h;
        add_header Cache-Control "public, max-age=3600";
    }
}
NGINXEOF

    if [[ ! -L /etc/nginx/sites-enabled/mgtravel ]]; then
        ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/mgtravel
    fi
    rm -f /etc/nginx/sites-enabled/default

    nginx -t && systemctl enable nginx && ok "Nginx configured."
}

# ─── FIREWALL ─────────────────────────────────────────────────────────────────
configure_firewall() {
    info "Configuring UFW firewall..."
    ufw --force reset   > /dev/null 2>&1
    ufw default deny incoming  > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp comment 'SSH'  > /dev/null 2>&1
    ufw allow 80/tcp comment 'HTTP' > /dev/null 2>&1
    ufw --force enable  > /dev/null 2>&1
    ok "UFW enabled: SSH(22) + HTTP(80) only."
}

# ─── SSH HARDENING ────────────────────────────────────────────────────────────
harden_ssh() {
    info "Hardening SSH configuration..."
    local sshd_conf="/etc/ssh/sshd_config"
    backup_file "$sshd_conf"

    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["ChallengeResponseAuthentication"]="no"
        ["UsePAM"]="yes"
        ["X11Forwarding"]="no"
        ["PrintMotd"]="no"
        ["MaxAuthTries"]="3"
        ["LoginGraceTime"]="30"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["AllowTcpForwarding"]="no"
        ["PermitEmptyPasswords"]="no"
    )

    for key in "${!ssh_settings[@]}"; do
        val="${ssh_settings[$key]}"
        if grep -qE "^#?${key}\s" "$sshd_conf"; then
            sed -i "s|^#\?${key}\s.*|${key} ${val}|" "$sshd_conf"
        else
            echo "${key} ${val}" >> "$sshd_conf"
        fi
    done

    sshd -t && ok "SSH hardened — key-based auth only, root login disabled."
}

# ─── FAIL2BAN ─────────────────────────────────────────────────────────────────
configure_fail2ban() {
    info "Configuring fail2ban..."
    cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime  = 1800
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s

[nginx-req-limit]
enabled  = true
filter   = nginx-req-limit
action   = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath  = /var/log/nginx/mgtravel_error.log
maxretry = 10
F2BEOF
    systemctl enable fail2ban
    ok "fail2ban configured."
}

# ─── LOG ROTATION ─────────────────────────────────────────────────────────────
configure_logging() {
    info "Configuring log rotation and journal limits..."

    cat > "$LOGROTATE_CONF" << 'LREOF'
/var/log/mgtravel/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    create 0640 mgtravel adm
    postrotate
        systemctl kill --kill-who=main --signal=USR1 mgtravel.service 2>/dev/null || true
    endscript
}
LREOF

    mkdir -p /etc/systemd/journald.conf.d
    cat > "$JOURNAL_CONF" << 'JEOF'
[Journal]
SystemMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
Compress=yes
JEOF

    systemctl restart systemd-journald 2>/dev/null || true
    ok "Log rotation and journal limits configured."
}

# ─── CLEANUP CRON ─────────────────────────────────────────────────────────────
configure_cleanup_cron() {
    info "Configuring automatic cleanup cron job..."
    local cron_file="/etc/cron.daily/mgtravel-cleanup"
    cat > "$cron_file" << 'CRONEOF'
#!/bin/bash
# MG Travel — Remove temp backup dirs older than 7 days
find /opt/mgtravel/backups -maxdepth 1 -name '*.tmp' -type d -mtime +7 \
    -exec rm -rf {} + 2>/dev/null || true
# Clean stale mountpoints
umount -l /mnt/mgtravel_src   2>/dev/null || true
umount -l /mnt/mgtravel_probe 2>/dev/null || true
CRONEOF
    chmod 750 "$cron_file"
    ok "Cleanup cron configured."
}

# ─── OPTIMIZE SERVICES ────────────────────────────────────────────────────────
optimize_services() {
    info "Disabling unnecessary services for low-RAM optimization..."
    local unwanted=(bluetooth hciuart triggerhappy wolfram-engine plymouth)
    for svc in "${unwanted[@]}"; do
        if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}"; then
            systemctl disable --now "${svc}.service" 2>/dev/null || true
            ok "Disabled: $svc"
        fi
    done

    if ! grep -q "vm.swappiness" /etc/sysctl.conf 2>/dev/null; then
        echo "vm.swappiness=10" >> /etc/sysctl.conf
        sysctl -w vm.swappiness=10 2>/dev/null || true
    fi
    ok "Service optimization complete."
}

# ─── HOSTNAME & AVAHI ────────────────────────────────────────────────────────
configure_hostname_avahi() {
    info "Configuring hostname and Avahi mDNS..."
    local current_hostname
    current_hostname=$(hostname)

    if [[ "$current_hostname" != "$HOSTNAME_NEW" ]]; then
        hostnamectl set-hostname "$HOSTNAME_NEW"
        sed -i "s/127\.0\.1\.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts
        grep -q "127.0.1.1" /etc/hosts || echo "127.0.1.1 ${HOSTNAME_NEW}" >> /etc/hosts
        ok "Hostname set to: $HOSTNAME_NEW"
    else
        ok "Hostname already set to: $HOSTNAME_NEW"
    fi

    if pkg_installed avahi-daemon; then
        backup_file /etc/avahi/avahi-daemon.conf
        cat > /etc/avahi/avahi-daemon.conf << 'AVAHIEOF'
[server]
host-name=mgtravel
domain-name=local
use-ipv4=yes
use-ipv6=no
allow-interfaces=eth0,wlan0
ratelimit-interval-usec=1000000
ratelimit-burst=1000

[wide-area]
enable-wide-area=no

[publish]
publish-addresses=yes
publish-hinfo=yes
publish-workstation=no
publish-domain=yes
disable-user-service-publishing=no

[rlimits]
rlimit-nproc=3
rlimit-nofile=30
rlimit-as=2M
AVAHIEOF
        systemctl enable avahi-daemon
        ok "Avahi configured — http://mgtravel.local/"
    fi
}

# ─── PERMISSIONS FINAL PASS ───────────────────────────────────────────────────
finalize_permissions() {
    info "Finalising file permissions..."

    # Stop the service if it's running – avoids interference
    systemctl stop mgtravel.service 2>/dev/null || true

    # ── App dir ownership ────────────────────────────────────────────────────
    chown -R "root:${APP_USER}" "${APP_DIR}"
    chmod 750 "${APP_DIR}"

    # ── Source files ─────────────────────────────────────────────────────────
    for f in app.py backup_engine.py device_manager.py verifier.py; do
        [[ -f "${APP_DIR}/${f}" ]] && chown "root:${APP_USER}" "${APP_DIR}/${f}" && chmod 640 "${APP_DIR}/${f}"
    done
    for d in templates static; do
        [[ -d "${APP_DIR}/${d}" ]] && chown -R "root:${APP_USER}" "${APP_DIR}/${d}"
        find "${APP_DIR}/${d}" -type d -exec chmod 750 {} \; 2>/dev/null || true
        find "${APP_DIR}/${d}" -type f -exec chmod 640 {} \; 2>/dev/null || true
    done

    # ── venv: 755 on directories and executables so mgtravel user can reach them
    # We use 755 (world-readable/executable) on the venv — the venv contains
    # no secrets, only installed packages. This is the standard approach and
    # avoids all group-membership / shebang-resolution permission issues.
    chown -R "root:root" "${APP_DIR}/venv"
    find "${APP_DIR}/venv" -type d -exec chmod 755 {} \;
    find "${APP_DIR}/venv" -type f -exec chmod 644 {} \;
    # Restore execute bits on all binaries and .so files
    find "${APP_DIR}/venv/bin" -type f -exec chmod 755 {} \;
    find "${APP_DIR}/venv/bin" -type l -exec chmod 755 {} \; 2>/dev/null || true
    find "${APP_DIR}/venv" -name "*.so"   -exec chmod 755 {} \;
    find "${APP_DIR}/venv" -name "*.so.*" -exec chmod 755 {} \;
    ok "venv permissions set."

    # ── Backups / logs ───────────────────────────────────────────────────────
    chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}/backups"
    chmod 750 "${APP_DIR}/backups"
    chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}/logs" 2>/dev/null || true
    chown -R "${APP_USER}:adm" /var/log/mgtravel
    chmod 750 /var/log/mgtravel

    # ── Sudoers ──────────────────────────────────────────────────────────────
    local sudoers_file="/etc/sudoers.d/mgtravel"
    local sudoers_line="${APP_USER} ALL=(root) NOPASSWD: /bin/mount, /bin/umount, /sbin/shutdown"
    if [[ ! -f "$sudoers_file" ]] || ! grep -qF "$sudoers_line" "$sudoers_file"; then
        echo "$sudoers_line" > "$sudoers_file"
        chmod 440 "$sudoers_file"
        ok "Sudoers entry created for mgtravel mount/umount/shutdown."
    fi

    # ── Verify python is executable by mgtravel ──────────────────────────────
    if sudo -u "$APP_USER" test -x "${APP_DIR}/venv/bin/python3"; then
        ok "Python binary is executable by $APP_USER."
    else
        warn "Python binary is NOT executable by $APP_USER. Aborting."
        ls -la "${APP_DIR}/venv/bin/python3" >&2
        echo "User $APP_USER groups: $(groups $APP_USER)" >&2
        exit 1
    fi

    ok "Permissions finalised."
}

# ─── START SERVICES ───────────────────────────────────────────────────────────
start_services() {
    info "Starting services..."
    systemctl daemon-reload

    for svc in nginx mgtravel fail2ban avahi-daemon; do
        if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}"; then
            systemctl restart "$svc" && ok "Started: $svc" || warn "Failed to start: $svc"
        fi
    done

    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

# ─── VERIFY INSTALLATION ──────────────────────────────────────────────────────
verify_installation() {
    info "Verifying installation..."
    local errors=0

    sleep 3

    for svc in nginx mgtravel; do
        if systemctl is-active --quiet "$svc"; then
            ok "Service running: $svc"
        else
            warn "Service NOT running: $svc"
            journalctl -u "$svc" -n 20 --no-pager
            ((errors++))
        fi
    done

    if curl -sf http://127.0.0.1/api/health -o /dev/null; then
        ok "HTTP health check passed."
    else
        warn "HTTP health check failed. Check nginx/mgtravel logs."
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        ok "All checks passed."
    else
        warn "$errors check(s) failed. Review logs above."
    fi
}

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
print_summary() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}') || ip="unknown"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          MG Travel — MG Servers · Installation Complete      ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Web UI      →  http://${ip}/"
    echo "║  Local DNS   →  http://mgtravel.local/"
    echo "║  Health API  →  http://${ip}/api/health"
    echo "║  Backups     →  ${APP_DIR}/backups/"
    echo "║  Logs        →  journalctl -u mgtravel -f"
    echo "║  Service     →  systemctl status mgtravel"
    echo "║  App user    →  ${APP_USER}"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  SSH key-based auth enforced · Root login disabled           ║"
    echo "║  UFW active: SSH(22) + HTTP(80) only                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
main() {
    log "╔══════════════════════════════════════════════════╗"
    log "║   MG Travel — MG Servers Install Script          ║"
    log "║   Raspberry Pi Zero 2W / Raspberry Pi OS Lite    ║"
    log "╚══════════════════════════════════════════════════╝"

    preflight_checks
    system_update
    install_packages
    create_app_user
    create_directories
    setup_python_env
    write_app_files
    configure_udev
    configure_systemd_service
    configure_nginx
    configure_firewall
    harden_ssh
    configure_fail2ban
    configure_logging
    configure_cleanup_cron
    optimize_services
    configure_hostname_avahi
    finalize_permissions
    start_services
    verify_installation
    print_summary
}

main "$@"
