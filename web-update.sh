#!/bin/bash
# update-dashboard.sh - Automatically updates MG Travel Security Dashboard with new features
# Run with sudo

set -e

# Configuration
APP_DIR="/opt/mg-travel-dashboard"
SERVICE_NAME="mg-travel-dashboard"
USERNAME="mg"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if installation exists
if [ ! -d "$APP_DIR" ]; then
    echo "Error: Dashboard not found in $APP_DIR"
    exit 1
fi

echo "=== Updating MG Travel Security Dashboard ==="

# Backup existing files
echo "Backing up current files..."
BACKUP_DIR="/tmp/mg-dashboard-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp "$APP_DIR/app.py" "$BACKUP_DIR/app.py.bak" 2>/dev/null || true
cp "$APP_DIR/templates/index.html" "$BACKUP_DIR/index.html.bak" 2>/dev/null || true
echo "Backup saved to $BACKUP_DIR"

# Install system dependencies
echo "Installing system packages..."
apt update
apt install -y arp-scan nmap

# Install Python dependencies
echo "Installing Python packages..."
source "$APP_DIR/venv/bin/activate"
pip install python-crontab python-nmap

# ========== Replace app.py with enhanced version ==========
echo "Updating Flask backend (app.py)..."

cat > "$APP_DIR/app.py" << 'EOF_PY'
#!/usr/bin/env python3
import os
import subprocess
import re
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psutil
import netifaces

import config

app = Flask(__name__)
app.config.from_object(config.Config)
socketio = SocketIO(app, cors_allowed_origins="*")
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# ---------- Authentication ----------
def tailscale_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if app.config['TAILSCALE_AUTH']:
            user = request.headers.get('Tailscale-User-Login')
            if user:
                return f(*args, **kwargs)
        if 'authenticated' in session:
            return f(*args, **kwargs)
        return redirect(url_for('login'))
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == app.config['FALLBACK_USER'] and password == app.config['FALLBACK_PASSWORD']:
            session['authenticated'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))

# ---------- Helper Functions ----------
def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1

def get_gateway_ip():
    gws = netifaces.gateways()
    if 'default' in gws and netifaces.AF_INET in gws['default']:
        return gws['default'][netifaces.AF_INET][0]
    return None

def get_gateway_mac(ip):
    try:
        out, _, _ = run_cmd(f"arp -n {ip}")
        for line in out.split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip:
                return parts[3]
    except:
        pass
    return None

def get_wifi_ssid():
    out, _, _ = run_cmd("iwgetid -r")
    return out.strip() or None

def get_tailscale_ip():
    out, _, _ = run_cmd("tailscale ip -4")
    return out.strip() or None

def get_service_status(service):
    out, _, rc = run_cmd(f"systemctl is-active {service}")
    return out.strip() if rc == 0 else 'inactive'

def read_anomalies(limit=50):
    logfile = app.config['ANOMALY_LOG']
    if not os.path.exists(logfile):
        return []
    with open(logfile, 'r') as f:
        lines = f.readlines()[-limit:]
    anomalies = []
    for line in lines:
        parts = line.strip().split(' ', 3)
        if len(parts) >= 4:
            anomalies.append({
                'timestamp': parts[0] + ' ' + parts[1],
                'type': parts[2].strip('[]'),
                'message': parts[3]
            })
    return anomalies

def get_bandwidth_history(hours=24):
    db = app.config['BANDWIDTH_DB']
    if not os.path.exists(db):
        return []
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT timestamp, rx, tx FROM bandwidth WHERE timestamp > datetime('now', ?) ORDER BY timestamp", (f'-{hours} hours',))
    rows = c.fetchall()
    conn.close()
    return [{'time': row[0], 'rx': row[1], 'tx': row[2]} for row in rows]

def get_tailscale_devices():
    out, _, rc = run_cmd("tailscale status --json")
    if rc != 0:
        return []
    try:
        data = json.loads(out)
        devices = []
        for peer_id, peer in data.get('Peer', {}).items():
            devices.append({
                'name': peer.get('HostName', ''),
                'ip': peer.get('TailscaleIPs', [''])[0],
                'os': peer.get('OS', ''),
                'online': peer.get('Online', False)
            })
        self = data.get('Self', {})
        devices.append({
            'name': self.get('HostName', ''),
            'ip': self.get('TailscaleIPs', [''])[0],
            'os': 'linux',
            'online': True
        })
        return devices
    except:
        return []

# ---------- Performance History Logger ----------
def background_perf_logger():
    db = app.config['BANDWIDTH_DB']
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS perf
                 (timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  cpu REAL, memory REAL, disk REAL)''')
    conn.commit()
    while True:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        c.execute("INSERT INTO perf (cpu, memory, disk) VALUES (?, ?, ?)", (cpu, mem, disk))
        conn.commit()
        socketio.sleep(60)

# ---------- API Endpoints ----------
@app.route('/')
@tailscale_auth_required
def index():
    return render_template('index.html')

@app.route('/api/system-info')
@limiter.limit("10 per minute")
@tailscale_auth_required
def system_info():
    local_ip = None
    for iface in netifaces.interfaces():
        if iface.startswith('wlan') or iface.startswith('eth'):
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
            if addrs:
                local_ip = addrs[0]['addr']
                break
    gateway_ip = get_gateway_ip()
    gateway_mac = get_gateway_mac(gateway_ip) if gateway_ip else None
    ssid = get_wifi_ssid()
    tailscale_ip = get_tailscale_ip()
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    services = {
        'ssh': get_service_status('ssh'),
        'fail2ban': get_service_status('fail2ban'),
        'ufw': run_cmd("ufw status | grep -q 'Status: active'")[2] == 0 if os.path.exists('/usr/sbin/ufw') else False,
        'watchdog': get_service_status('watchdog')
    }
    return jsonify({
        'local_ip': local_ip,
        'gateway_ip': gateway_ip,
        'gateway_mac': gateway_mac,
        'ssid': ssid,
        'tailscale_ip': tailscale_ip,
        'cpu': cpu,
        'memory': mem,
        'disk': disk,
        'services': services
    })

@app.route('/api/anomalies')
@limiter.limit("20 per minute")
@tailscale_auth_required
def anomalies():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(read_anomalies(limit))

@app.route('/api/bandwidth')
@limiter.limit("20 per minute")
@tailscale_auth_required
def bandwidth():
    hours = request.args.get('hours', 24, type=int)
    data = get_bandwidth_history(hours)
    if not data:
        # Fallback sample data
        now = datetime.now()
        data = []
        for i in range(hours):
            t = now - timedelta(hours=hours-i-1)
            data.append({
                'time': t.isoformat(),
                'rx': 500 + i * 10,
                'tx': 300 + i * 5
            })
    return jsonify(data)

@app.route('/api/wifi/networks')
@limiter.limit("5 per minute")
@tailscale_auth_required
def wifi_networks():
    out, err, rc = run_cmd("sudo iwlist wlan0 scan")
    if rc != 0:
        return jsonify({'error': 'Could not scan', 'details': err}), 500
    networks = []
    for block in out.split('Cell '):
        if 'Address:' in block:
            ssid_match = re.search(r'ESSID:"(.+)"', block)
            if not ssid_match:
                continue
            ssid = ssid_match.group(1)
            signal_match = re.search(r'Signal level=(-?\d+)', block)
            signal = int(signal_match.group(1)) if signal_match else 0
            encrypted = 'Encryption key:on' in block
            networks.append({'ssid': ssid, 'signal': signal, 'encrypted': encrypted})
    return jsonify(sorted(networks, key=lambda x: x['signal'], reverse=True))

@app.route('/api/wifi/connect', methods=['POST'])
@limiter.limit("3 per minute")
@tailscale_auth_required
def wifi_connect():
    data = request.get_json()
    ssid = data.get('ssid')
    psk = data.get('psk')
    if not ssid:
        return jsonify({'error': 'SSID required'}), 400
    config_line = f'network={{\n\tssid="{ssid}"\n\tpsk="{psk}"\n}}\n'
    try:
        with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'a') as f:
            f.write(config_line)
        run_cmd("wpa_cli reconfigure")
        return jsonify({'status': 'connecting'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<name>/<action>', methods=['POST'])
@limiter.limit("10 per minute")
@tailscale_auth_required
def service_control(name, action):
    valid_services = ['ssh', 'fail2ban', 'ufw', 'watchdog']
    if name not in valid_services:
        return jsonify({'error': 'Invalid service'}), 400
    if action not in ['start', 'stop', 'restart', 'status', 'enable', 'disable']:
        return jsonify({'error': 'Invalid action'}), 400
    if name == 'ufw':
        if not os.path.exists('/usr/sbin/ufw'):
            return jsonify({'error': 'UFW is not installed'}), 400
        if action == 'status':
            cmd = "ufw status"
        else:
            cmd = f"ufw --force {action}"
    else:
        cmd = f"systemctl {action} {name}"
    out, err, rc = run_cmd(cmd)
    return jsonify({'output': out, 'error': err, 'returncode': rc})

@app.route('/api/system/reboot', methods=['POST'])
@limiter.limit("1 per minute")
@tailscale_auth_required
def reboot():
    run_cmd("sudo shutdown -r now")
    return jsonify({'status': 'rebooting'})

@app.route('/api/system/shutdown', methods=['POST'])
@limiter.limit("1 per minute")
@tailscale_auth_required
def shutdown():
    run_cmd("sudo shutdown -h now")
    return jsonify({'status': 'shutting down'})

@app.route('/api/tailscale/devices')
@limiter.limit("10 per minute")
@tailscale_auth_required
def tailscale_devices():
    return jsonify(get_tailscale_devices())

@app.route('/api/tailscale/exit-node', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def set_exit_node():
    data = request.get_json()
    node_ip = data.get('node_ip')
    if node_ip:
        run_cmd(f"tailscale set --exit-node={node_ip}")
    else:
        run_cmd("tailscale set --exit-node=")
    return jsonify({'status': 'updated'})

# ---------- New Security Management Endpoints ----------

# UFW Rules
@app.route('/api/ufw/rules')
@limiter.limit("10 per minute")
@tailscale_auth_required
def ufw_rules():
    out, err, rc = run_cmd("ufw status numbered")
    if rc != 0:
        return jsonify({'error': err}), 500
    rules = []
    for line in out.split('\n'):
        if line.strip() and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 4:
                rules.append({
                    'number': parts[0].strip('[]'),
                    'action': parts[1],
                    'from': parts[2],
                    'to': parts[3] if len(parts) > 3 else ''
                })
    return jsonify(rules)

@app.route('/api/ufw/rule', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def ufw_add_rule():
    data = request.get_json()
    rule = data.get('rule')
    if not rule:
        return jsonify({'error': 'Rule required'}), 400
    out, err, rc = run_cmd(f"ufw {rule}")
    return jsonify({'output': out, 'error': err, 'returncode': rc})

@app.route('/api/ufw/rule/<int:num>', methods=['DELETE'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def ufw_delete_rule(num):
    out, err, rc = run_cmd(f"ufw --force delete {num}")
    return jsonify({'output': out, 'error': err, 'returncode': rc})

# Fail2Ban Jails
@app.route('/api/fail2ban/jails')
@limiter.limit("10 per minute")
@tailscale_auth_required
def fail2ban_jails():
    out, err, rc = run_cmd("fail2ban-client status")
    if rc != 0:
        return jsonify({'error': err}), 500
    jails = []
    for line in out.split('\n'):
        if 'Jail list:' in line:
            jails = [j.strip() for j in line.split('Jail list:')[1].strip().split(',') if j.strip()]
            break
    jail_status = []
    for jail in jails:
        status_out, _, _ = run_cmd(f"fail2ban-client status {jail}")
        jail_status.append({'name': jail, 'status': status_out})
    return jsonify(jail_status)

@app.route('/api/fail2ban/unban', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def fail2ban_unban():
    data = request.get_json()
    jail = data.get('jail')
    ip = data.get('ip')
    if not jail or not ip:
        return jsonify({'error': 'Jail and IP required'}), 400
    out, err, rc = run_cmd(f"fail2ban-client set {jail} unbanip {ip}")
    return jsonify({'output': out, 'error': err, 'returncode': rc})

# Watchdog kick
@app.route('/api/watchdog/kick', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def watchdog_kick():
    try:
        with open('/dev/watchdog', 'w') as f:
            f.write('V')
        return jsonify({'status': 'kicked'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Network scan (ARP-SCAN)
@app.route('/api/network/devices')
@limiter.limit("5 per minute")
@tailscale_auth_required
def network_devices():
    out, err, rc = run_cmd("sudo arp-scan --localnet --numeric --ignoredups")
    if rc != 0:
        return jsonify({'error': err}), 500
    devices = []
    for line in out.split('\n'):
        parts = line.split()
        if len(parts) >= 3 and parts[1].count('.') == 3:
            devices.append({
                'ip': parts[0],
                'mac': parts[1],
                'vendor': ' '.join(parts[2:])
            })
    return jsonify(devices)

# Cron jobs
@app.route('/api/cron')
@limiter.limit("10 per minute")
@tailscale_auth_required
def cron_list():
    out, err, rc = run_cmd("crontab -l")
    if rc != 0 and "no crontab" not in err:
        return jsonify({'error': err}), 500
    jobs = []
    for line in out.split('\n'):
        if line.strip() and not line.startswith('#'):
            jobs.append(line)
    return jsonify(jobs)

@app.route('/api/cron', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def cron_add():
    data = request.get_json()
    job = data.get('job')
    if not job:
        return jsonify({'error': 'Job line required'}), 400
    current, _, _ = run_cmd("crontab -l")
    new_crontab = current + '\n' + job + '\n'
    proc = subprocess.run(f"echo '{new_crontab}' | crontab -", shell=True, capture_output=True, text=True)
    if proc.returncode != 0:
        return jsonify({'error': proc.stderr}), 500
    return jsonify({'status': 'added'})

@app.route('/api/cron', methods=['DELETE'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def cron_remove():
    data = request.get_json()
    job_line = data.get('job')
    if not job_line:
        return jsonify({'error': 'Job line required'}), 400
    current, _, _ = run_cmd("crontab -l")
    new_lines = [line for line in current.split('\n') if line.strip() != job_line.strip()]
    new_crontab = '\n'.join(new_lines) + '\n'
    proc = subprocess.run(f"echo '{new_crontab}' | crontab -", shell=True, capture_output=True, text=True)
    if proc.returncode != 0:
        return jsonify({'error': proc.stderr}), 500
    return jsonify({'status': 'removed'})

# System updates
@app.route('/api/updates/check', methods=['POST'])
@limiter.limit("3 per minute")
@tailscale_auth_required
def updates_check():
    run_cmd("apt update")
    out, err, rc = run_cmd("apt list --upgradable")
    upgradable = []
    for line in out.split('\n'):
        if '/' in line:
            parts = line.split()
            if len(parts) >= 2:
                upgradable.append({'package': parts[0], 'version': parts[1]})
    return jsonify({'upgradable': upgradable})

@app.route('/api/updates/upgrade', methods=['POST'])
@limiter.limit("1 per minute")
@tailscale_auth_required
def updates_upgrade():
    out, err, rc = run_cmd("apt upgrade -y")
    return jsonify({'output': out, 'error': err, 'returncode': rc})

# Performance history
@app.route('/api/perf/history')
@limiter.limit("20 per minute")
@tailscale_auth_required
def perf_history():
    hours = request.args.get('hours', 24, type=int)
    db = app.config['BANDWIDTH_DB']
    if not os.path.exists(db):
        return jsonify([])
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT timestamp, cpu, memory, disk FROM perf WHERE timestamp > datetime('now', ?) ORDER BY timestamp", (f'-{hours} hours',))
    rows = c.fetchall()
    conn.close()
    return jsonify([{'time': row[0], 'cpu': row[1], 'memory': row[2], 'disk': row[3]} for row in rows])

# Tailscale advertise exit node
@app.route('/api/tailscale/advertise-exit', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def tailscale_advertise_exit():
    data = request.get_json()
    advertise = data.get('advertise', False)
    if advertise:
        run_cmd("tailscale set --advertise-exit-node")
    else:
        run_cmd("tailscale set --advertise-exit-node=false")
    return jsonify({'status': 'updated'})

# Tailscale routes
@app.route('/api/tailscale/routes', methods=['POST'])
@limiter.limit("5 per minute")
@tailscale_auth_required
def tailscale_routes():
    data = request.get_json()
    route = data.get('route')
    if route:
        run_cmd(f"tailscale set --advertise-routes={route}")
    return jsonify({'status': 'updated'})

# ---------- Logs ----------
@app.route('/api/logs/<service>')
@limiter.limit("20 per minute")
@tailscale_auth_required
def get_logs(service):
    lines = request.args.get('lines', 100, type=int)
    if service == 'anomalies':
        logfile = app.config['ANOMALY_LOG']
    else:
        logfile = f"/var/log/{service}.log"
    if not os.path.exists(logfile):
        return jsonify({'logs': ''})
    out, _, _ = run_cmd(f"tail -n {lines} {logfile}")
    return jsonify({'logs': out})

# ---------- WebSocket ----------
@socketio.on('connect')
def handle_connect():
    emit('message', {'data': 'Connected'})

def background_bandwidth_thread():
    while True:
        counters = psutil.net_io_counters(pernic=True)
        if 'wlan0' in counters:
            rx = counters['wlan0'].bytes_recv
            tx = counters['wlan0'].bytes_sent
            socketio.emit('bandwidth_update', {'rx': rx, 'tx': tx})
        socketio.sleep(5)

def background_anomaly_thread():
    logfile = app.config['ANOMALY_LOG']
    if not os.path.exists(logfile):
        return
    with open(logfile, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                socketio.emit('anomaly', {'line': line.strip()})
            else:
                socketio.sleep(1)

@socketio.on('start_live_bandwidth')
def start_live_bandwidth():
    socketio.start_background_task(background_bandwidth_thread)

@socketio.on('start_live_anomalies')
def start_live_anomalies():
    socketio.start_background_task(background_anomaly_thread)

# ---------- Error Handlers ----------
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Start performance logger in background
    socketio.start_background_task(background_perf_logger)
    socketio.run(app, host='0.0.0.0', port=8443, ssl_context=('certs/cert.pem', 'certs/key.pem'), debug=False, allow_unsafe_werkzeug=True)
EOF_PY

# ========== Replace index.html with enhanced version ==========
echo "Updating frontend (index.html)..."

cat > "$APP_DIR/templates/index.html" << 'EOF_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>MG Travel Security Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        * { transition: background-color 0.2s ease, border-color 0.2s ease; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        .dark ::-webkit-scrollbar-track { background: #0f172a; }
        .dark ::-webkit-scrollbar-thumb { background: #334155; }
    </style>
</head>
<body class="bg-slate-100 dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-sans antialiased">
    <nav class="bg-white/70 dark:bg-slate-800/70 backdrop-blur-md shadow-sm sticky top-0 z-50 border-b border-slate-200 dark:border-slate-700">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <div class="flex items-center space-x-4">
                    <i class="fas fa-shield-haltered text-2xl text-cyan-600 dark:text-cyan-400"></i>
                    <span class="font-bold text-xl">MG Travel Security</span>
                </div>
                <div class="flex items-center space-x-2">
                    <button id="theme-toggle" class="p-2 rounded-lg bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600">
                        <i class="fas fa-moon dark:hidden"></i>
                        <i class="fas fa-sun hidden dark:inline"></i>
                    </button>
                    <a href="/logout" class="px-4 py-2 rounded-lg bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-500/20">Logout</a>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        <!-- System Status Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-slate-500 dark:text-slate-400">Local IP</p>
                        <p id="local-ip" class="text-lg font-mono font-semibold">-</p>
                    </div>
                    <i class="fas fa-network-wired text-3xl text-cyan-500"></i>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-slate-500 dark:text-slate-400">Gateway</p>
                        <p id="gateway-ip" class="text-lg font-mono font-semibold">-</p>
                    </div>
                    <i class="fas fa-route text-3xl text-cyan-500"></i>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-slate-500 dark:text-slate-400">WiFi SSID</p>
                        <p id="ssid" class="text-lg font-semibold">-</p>
                    </div>
                    <i class="fas fa-wifi text-3xl text-cyan-500"></i>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-slate-500 dark:text-slate-400">Tailscale IP</p>
                        <p id="tailscale-ip" class="text-lg font-mono font-semibold">-</p>
                    </div>
                    <i class="fab fa-tailscale text-3xl text-cyan-500"></i>
                </div>
            </div>
        </div>

        <!-- Resource Usage + Services -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-2 bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">System Resources</h3>
                <div class="space-y-4">
                    <div>
                        <div class="flex justify-between mb-1"><span>CPU</span><span id="cpu" class="font-mono">0%</span></div>
                        <div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2.5"><div id="cpu-bar" class="bg-cyan-500 h-2.5 rounded-full" style="width:0%"></div></div>
                    </div>
                    <div>
                        <div class="flex justify-between mb-1"><span>Memory</span><span id="memory" class="font-mono">0%</span></div>
                        <div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2.5"><div id="memory-bar" class="bg-cyan-500 h-2.5 rounded-full" style="width:0%"></div></div>
                    </div>
                    <div>
                        <div class="flex justify-between mb-1"><span>Disk</span><span id="disk" class="font-mono">0%</span></div>
                        <div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2.5"><div id="disk-bar" class="bg-cyan-500 h-2.5 rounded-full" style="width:0%"></div></div>
                    </div>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">Services</h3>
                <div class="space-y-3">
                    <div class="flex justify-between items-center">
                        <span>SSH</span>
                        <span id="ssh-status" class="px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-700 dark:text-green-400">-</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span>Fail2Ban</span>
                        <span id="fail2ban-status" class="px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-700 dark:text-green-400">-</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span>UFW</span>
                        <span id="ufw-status" class="px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-700 dark:text-green-400">-</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span>Watchdog</span>
                        <span id="watchdog-status" class="px-3 py-1 rounded-full text-sm bg-green-500/20 text-green-700 dark:text-green-400">-</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Bandwidth Chart -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Bandwidth (last 24h)</h3>
            <canvas id="bandwidthChart" class="w-full h-64"></canvas>
        </div>

        <!-- Performance History Chart (new) -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Performance History (last 24h)</h3>
            <canvas id="perfChart" class="w-full h-64"></canvas>
        </div>

        <!-- Anomalies + Alerts -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">Recent Anomalies</h3>
                <div id="anomaly-list" class="space-y-2 max-h-80 overflow-y-auto pr-2">
                    <div class="text-slate-500 dark:text-slate-400">Loading...</div>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">Live Alerts</h3>
                <div id="live-alerts" class="space-y-2 max-h-80 overflow-y-auto pr-2">
                    <div class="text-slate-500 dark:text-slate-400">Waiting for alerts...</div>
                </div>
            </div>
        </div>

        <!-- WiFi Networks -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Available WiFi Networks</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
                    <thead><tr><th class="text-left py-2">SSID</th><th class="text-left">Signal</th><th class="text-left">Encrypted</th><th class="text-left">Action</th></tr></thead>
                    <tbody id="wifi-list" class="divide-y divide-slate-200 dark:divide-slate-700"></tbody>
                </table>
            </div>
            <form id="wifi-connect-form" class="mt-4 flex flex-col sm:flex-row gap-2">
                <input type="text" id="wifi-ssid" placeholder="SSID" class="flex-1 px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600">
                <input type="password" id="wifi-psk" placeholder="Password" class="flex-1 px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600">
                <button type="submit" class="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Connect</button>
            </form>
        </div>

        <!-- UFW Rules -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">UFW Rules</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
                    <thead><tr><th>#</th><th>Action</th><th>From</th><th>To</th><th></th></tr></thead>
                    <tbody id="ufw-rules-list"></tbody>
                </table>
            </div>
            <form id="ufw-add-rule" class="mt-4 flex flex-col sm:flex-row gap-2">
                <input type="text" id="ufw-rule" placeholder="e.g., allow 22/tcp" class="flex-1 px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-700 border">
                <button type="submit" class="px-6 py-2 bg-cyan-600 text-white rounded-lg">Add Rule</button>
            </form>
        </div>

        <!-- Fail2Ban Jails -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Fail2Ban Jails</h3>
            <div id="fail2ban-jails-list" class="space-y-2"></div>
        </div>

        <!-- Network Scan -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Local Network Devices</h3>
            <button onclick="scanNetwork()" class="mb-2 px-4 py-2 bg-cyan-600 text-white rounded-lg">Scan Now</button>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
                    <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th></tr></thead>
                    <tbody id="network-devices-list"></tbody>
                </table>
            </div>
        </div>

        <!-- Cron Jobs -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Cron Jobs</h3>
            <div id="cron-jobs-list" class="space-y-1"></div>
            <form id="cron-add-job" class="mt-4 flex flex-col sm:flex-row gap-2">
                <input type="text" id="cron-job" placeholder="* * * * * /path/to/script" class="flex-1 px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-700 border">
                <button type="submit" class="px-6 py-2 bg-cyan-600 text-white rounded-lg">Add Job</button>
            </form>
        </div>

        <!-- System Updates -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">System Updates</h3>
            <button onclick="checkUpdates()" class="mb-2 px-4 py-2 bg-cyan-600 text-white rounded-lg">Check Updates</button>
            <button onclick="upgradeSystem()" class="mb-2 px-4 py-2 bg-amber-600 text-white rounded-lg">Upgrade All</button>
            <div id="updates-list" class="text-sm"></div>
        </div>

        <!-- Tailscale Devices -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-lg font-semibold">Tailscale Devices</h3>
                <button onclick="refreshTailscale()" class="px-3 py-1 bg-slate-200 dark:bg-slate-700 rounded-lg"><i class="fas fa-sync-alt"></i></button>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
                    <thead><tr><th class="text-left py-2">Name</th><th class="text-left">IP</th><th class="text-left">OS</th><th class="text-left">Status</th><th class="text-left">Exit Node</th></tr></thead>
                    <tbody id="tailscale-list" class="divide-y divide-slate-200 dark:divide-slate-700"></tbody>
                </table>
            </div>
            <div class="mt-2">
                <button onclick="advertiseExitNode()" class="px-3 py-1 bg-cyan-600 text-white rounded-lg">Advertise as Exit Node</button>
            </div>
        </div>

        <!-- Service Controls + Power -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">Service Controls</h3>
                <div class="space-y-3">
                    <div class="flex items-center justify-between">
                        <span>SSH</span>
                        <div><button onclick="controlService('ssh','start')" class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded-l-lg">Start</button><button onclick="controlService('ssh','stop')" class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white">Stop</button><button onclick="controlService('ssh','restart')" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-r-lg">Restart</button></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span>Fail2Ban</span>
                        <div><button onclick="controlService('fail2ban','start')" class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded-l-lg">Start</button><button onclick="controlService('fail2ban','stop')" class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white">Stop</button><button onclick="controlService('fail2ban','restart')" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-r-lg">Restart</button></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span>UFW</span>
                        <div><button onclick="controlService('ufw','enable')" class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded-l-lg">Enable</button><button onclick="controlService('ufw','disable')" class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white">Disable</button><button onclick="controlService('ufw','status')" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-r-lg">Status</button></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span>Watchdog</span>
                        <div><button onclick="controlService('watchdog','start')" class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded-l-lg">Start</button><button onclick="controlService('watchdog','stop')" class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white">Stop</button><button onclick="controlService('watchdog','restart')" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-r-lg">Restart</button></div>
                    </div>
                </div>
            </div>
            <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
                <h3 class="text-lg font-semibold mb-4">System Power</h3>
                <div class="flex gap-3">
                    <button onclick="powerAction('reboot')" class="flex-1 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg"><i class="fas fa-sync-alt mr-2"></i>Reboot</button>
                    <button onclick="powerAction('shutdown')" class="flex-1 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"><i class="fas fa-power-off mr-2"></i>Shutdown</button>
                </div>
            </div>
        </div>

        <!-- Log Viewer -->
        <div class="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-2xl shadow-lg p-5 border border-slate-200 dark:border-slate-700">
            <h3 class="text-lg font-semibold mb-4">Log Viewer</h3>
            <div class="flex flex-col sm:flex-row gap-2 mb-4">
                <select id="log-service" class="px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600">
                    <option value="anomalies">Anomalies</option>
                    <option value="syslog">System Log</option>
                    <option value="auth">Auth Log</option>
                </select>
                <button onclick="fetchLogs()" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Load Logs</button>
                <button onclick="exportLogs()" class="px-4 py-2 bg-slate-600 hover:bg-slate-700 text-white rounded-lg">Export JSON</button>
            </div>
            <textarea id="log-content" class="w-full h-64 p-3 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 font-mono text-sm" readonly></textarea>
        </div>
    </main>

    <div id="toast-container" class="fixed bottom-4 right-4 z-50 space-y-2"></div>

    <script>
        const socket = io();
        let bandwidthChart, perfChart;

        // Theme toggle
        const themeToggle = document.getElementById('theme-toggle');
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        themeToggle.addEventListener('click', () => {
            document.documentElement.classList.toggle('dark');
            localStorage.theme = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
        });

        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = `px-4 py-3 rounded-lg shadow-lg text-white ${type === 'error' ? 'bg-red-600' : type === 'success' ? 'bg-green-600' : 'bg-blue-600'} transition-opacity duration-300`;
            toast.textContent = message;
            document.getElementById('toast-container').appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        }

        // System Info
        async function fetchSystemInfo() {
            try {
                const res = await fetch('/api/system-info');
                if (!res.ok) throw new Error('Failed to fetch');
                const data = await res.json();
                document.getElementById('local-ip').textContent = data.local_ip || '-';
                document.getElementById('gateway-ip').textContent = data.gateway_ip || '-';
                document.getElementById('ssid').textContent = data.ssid || '-';
                document.getElementById('tailscale-ip').textContent = data.tailscale_ip || '-';
                document.getElementById('cpu').textContent = data.cpu + '%';
                document.getElementById('memory').textContent = data.memory + '%';
                document.getElementById('disk').textContent = data.disk + '%';
                document.getElementById('cpu-bar').style.width = data.cpu + '%';
                document.getElementById('memory-bar').style.width = data.memory + '%';
                document.getElementById('disk-bar').style.width = data.disk + '%';
                updateServiceBadges(data.services);
            } catch (err) {
                showToast('Error loading system info', 'error');
            }
        }

        function updateServiceBadges(services) {
            for (let [srv, status] of Object.entries(services)) {
                const el = document.getElementById(srv + '-status');
                if (el) {
                    const active = status === 'active' || status === true;
                    el.textContent = active ? 'active' : 'inactive';
                    el.className = `px-3 py-1 rounded-full text-sm ${active ? 'bg-green-500/20 text-green-700 dark:text-green-400' : 'bg-red-500/20 text-red-700 dark:text-red-400'}`;
                }
            }
        }

        // Bandwidth Chart (fixed)
        async function fetchBandwidth() {
            try {
                const res = await fetch('/api/bandwidth?hours=24');
                const data = await res.json();
                const times = data.map(d => new Date(d.time).toLocaleTimeString());
                const rx = data.map(d => d.rx);
                const tx = data.map(d => d.tx);
                if (bandwidthChart) bandwidthChart.destroy();
                const ctx = document.getElementById('bandwidthChart').getContext('2d');
                bandwidthChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: times,
                        datasets: [
                            { label: 'RX (KB/s)', data: rx, borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.1)', tension: 0.3, fill: true },
                            { label: 'TX (KB/s)', data: tx, borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.1)', tension: 0.3, fill: true }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: document.documentElement.classList.contains('dark') ? '#e2e8f0' : '#1e293b' } } },
                        scales: { x: { ticks: { color: document.documentElement.classList.contains('dark') ? '#94a3b8' : '#475569' } },
                                 y: { ticks: { color: document.documentElement.classList.contains('dark') ? '#94a3b8' : '#475569' } } }
                    }
                });
            } catch (err) {
                showToast('Error loading bandwidth', 'error');
            }
        }

        // Performance History Chart
        async function fetchPerfHistory() {
            try {
                const res = await fetch('/api/perf/history?hours=24');
                const data = await res.json();
                const times = data.map(d => new Date(d.time).toLocaleTimeString());
                const cpu = data.map(d => d.cpu);
                const mem = data.map(d => d.memory);
                const disk = data.map(d => d.disk);
                if (perfChart) perfChart.destroy();
                const ctx = document.getElementById('perfChart').getContext('2d');
                perfChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: times,
                        datasets: [
                            { label: 'CPU %', data: cpu, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', tension: 0.3, fill: true },
                            { label: 'Memory %', data: mem, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', tension: 0.3, fill: true },
                            { label: 'Disk %', data: disk, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', tension: 0.3, fill: true }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: document.documentElement.classList.contains('dark') ? '#e2e8f0' : '#1e293b' } } },
                        scales: { x: { ticks: { color: document.documentElement.classList.contains('dark') ? '#94a3b8' : '#475569' } },
                                 y: { ticks: { color: document.documentElement.classList.contains('dark') ? '#94a3b8' : '#475569' } } }
                    }
                });
            } catch (err) {
                showToast('Error loading performance history', 'error');
            }
        }

        // Anomalies
        async function fetchAnomalies() {
            try {
                const res = await fetch('/api/anomalies?limit=10');
                const data = await res.json();
                const list = document.getElementById('anomaly-list');
                list.innerHTML = '';
                if (data.length === 0) {
                    list.innerHTML = '<div class="text-slate-500 dark:text-slate-400">No anomalies</div>';
                } else {
                    data.forEach(a => {
                        const div = document.createElement('div');
                        div.className = 'p-2 bg-slate-100 dark:bg-slate-700 rounded-lg text-sm';
                        div.innerHTML = `<span class="font-mono text-xs text-slate-500 dark:text-slate-400">${a.timestamp}</span> [${a.type}] ${a.message}`;
                        list.appendChild(div);
                    });
                }
            } catch (err) {
                showToast('Error loading anomalies', 'error');
            }
        }

        // WiFi
        async function fetchWiFi() {
            try {
                const res = await fetch('/api/wifi/networks');
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                const tbody = document.getElementById('wifi-list');
                tbody.innerHTML = '';
                data.forEach(net => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="py-2">${net.ssid}</td>
                        <td>${net.signal} dBm</td>
                        <td>${net.encrypted ? 'Yes' : 'No'}</td>
                        <td><button onclick="connectTo('${net.ssid}')" class="px-3 py-1 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm">Connect</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                showToast('WiFi scan failed: ' + err.message, 'error');
            }
        }

        function connectTo(ssid) {
            document.getElementById('wifi-ssid').value = ssid;
        }

        document.getElementById('wifi-connect-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ssid = document.getElementById('wifi-ssid').value;
            const psk = document.getElementById('wifi-psk').value;
            try {
                const res = await fetch('/api/wifi/connect', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ssid, psk})
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                showToast('Connecting to ' + ssid, 'success');
                fetchWiFi();
            } catch (err) {
                showToast('Connection failed: ' + err.message, 'error');
            }
        });

        // UFW Rules
        async function fetchUfwRules() {
            try {
                const res = await fetch('/api/ufw/rules');
                const data = await res.json();
                const tbody = document.getElementById('ufw-rules-list');
                tbody.innerHTML = '';
                data.forEach(rule => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${rule.number}</td>
                        <td>${rule.action}</td>
                        <td>${rule.from}</td>
                        <td>${rule.to}</td>
                        <td><button onclick="deleteUfwRule('${rule.number}')" class="text-red-500"><i class="fas fa-trash"></i></button></td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                showToast('Error loading UFW rules', 'error');
            }
        }

        document.getElementById('ufw-add-rule').addEventListener('submit', async (e) => {
            e.preventDefault();
            const rule = document.getElementById('ufw-rule').value;
            if (!rule) return;
            try {
                const res = await fetch('/api/ufw/rule', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({rule})
                });
                const data = await res.json();
                if (data.returncode === 0) {
                    showToast('Rule added', 'success');
                    fetchUfwRules();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (err) {
                showToast('Failed to add rule', 'error');
            }
        });

        async function deleteUfwRule(num) {
            if (!confirm(`Delete rule ${num}?`)) return;
            try {
                const res = await fetch(`/api/ufw/rule/${num}`, {method: 'DELETE'});
                const data = await res.json();
                if (data.returncode === 0) {
                    showToast('Rule deleted', 'success');
                    fetchUfwRules();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (err) {
                showToast('Failed to delete rule', 'error');
            }
        }

        // Fail2Ban Jails
        async function fetchFail2banJails() {
            try {
                const res = await fetch('/api/fail2ban/jails');
                const data = await res.json();
                const container = document.getElementById('fail2ban-jails-list');
                container.innerHTML = '';
                data.forEach(jail => {
                    const div = document.createElement('div');
                    div.className = 'p-2 bg-slate-100 dark:bg-slate-700 rounded';
                    div.innerHTML = `<strong>${jail.name}</strong><pre class="text-xs overflow-x-auto">${jail.status}</pre>`;
                    container.appendChild(div);
                });
            } catch (err) {
                showToast('Error loading Fail2Ban jails', 'error');
            }
        }

        // Network Scan
        async function scanNetwork() {
            try {
                const res = await fetch('/api/network/devices');
                const data = await res.json();
                const tbody = document.getElementById('network-devices-list');
                tbody.innerHTML = '';
                data.forEach(dev => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>${dev.ip}</td><td>${dev.mac}</td><td>${dev.vendor}</td>`;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                showToast('Network scan failed', 'error');
            }
        }

        // Cron Jobs
        async function fetchCronJobs() {
            try {
                const res = await fetch('/api/cron');
                const data = await res.json();
                const container = document.getElementById('cron-jobs-list');
                container.innerHTML = '';
                data.forEach(job => {
                    const div = document.createElement('div');
                    div.className = 'flex justify-between items-center p-1 bg-slate-100 dark:bg-slate-700 rounded';
                    div.innerHTML = `<span class="text-sm">${job}</span><button onclick="deleteCronJob('${job}')" class="text-red-500"><i class="fas fa-times"></i></button>`;
                    container.appendChild(div);
                });
            } catch (err) {
                showToast('Error loading cron jobs', 'error');
            }
        }

        document.getElementById('cron-add-job').addEventListener('submit', async (e) => {
            e.preventDefault();
            const job = document.getElementById('cron-job').value;
            if (!job) return;
            try {
                const res = await fetch('/api/cron', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({job})
                });
                const data = await res.json();
                if (data.status === 'added') {
                    showToast('Cron job added', 'success');
                    fetchCronJobs();
                } else {
                    showToast('Error adding cron job', 'error');
                }
            } catch (err) {
                showToast('Failed to add cron job', 'error');
            }
        });

        async function deleteCronJob(job) {
            if (!confirm('Delete this cron job?')) return;
            try {
                const res = await fetch('/api/cron', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({job})
                });
                const data = await res.json();
                if (data.status === 'removed') {
                    showToast('Cron job removed', 'success');
                    fetchCronJobs();
                } else {
                    showToast('Error removing cron job', 'error');
                }
            } catch (err) {
                showToast('Failed to remove cron job', 'error');
            }
        }

        // Updates
        async function checkUpdates() {
            try {
                const res = await fetch('/api/updates/check', {method: 'POST'});
                const data = await res.json();
                const list = document.getElementById('updates-list');
                if (data.upgradable.length === 0) {
                    list.innerHTML = '<p>No updates available</p>';
                } else {
                    list.innerHTML = '<ul>' + data.upgradable.map(p => `<li>${p.package} (${p.version})</li>`).join('') + '</ul>';
                }
            } catch (err) {
                showToast('Error checking updates', 'error');
            }
        }

        async function upgradeSystem() {
            if (!confirm('Upgrade all packages? This may take a while.')) return;
            try {
                const res = await fetch('/api/updates/upgrade', {method: 'POST'});
                const data = await res.json();
                showToast('Upgrade completed', 'success');
            } catch (err) {
                showToast('Upgrade failed', 'error');
            }
        }

        // Tailscale
        async function fetchTailscale() {
            try {
                const res = await fetch('/api/tailscale/devices');
                const data = await res.json();
                const tbody = document.getElementById('tailscale-list');
                tbody.innerHTML = '';
                data.forEach(dev => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="py-2">${dev.name}</td>
                        <td>${dev.ip}</td>
                        <td>${dev.os}</td>
                        <td><span class="px-2 py-1 rounded-full text-xs ${dev.online ? 'bg-green-500/20 text-green-700' : 'bg-slate-500/20 text-slate-700'}">${dev.online ? 'Online' : 'Offline'}</span></td>
                        <td><button onclick="setExitNode('${dev.ip}')" class="px-2 py-1 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-xs">Set Exit</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                showToast('Error loading Tailscale devices', 'error');
            }
        }

        async function setExitNode(ip) {
            try {
                await fetch('/api/tailscale/exit-node', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({node_ip: ip})
                });
                showToast('Exit node set to ' + ip, 'success');
            } catch (err) {
                showToast('Failed to set exit node', 'error');
            }
        }

        async function advertiseExitNode() {
            try {
                await fetch('/api/tailscale/advertise-exit', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({advertise: true})
                });
                showToast('Advertising as exit node', 'success');
            } catch (err) {
                showToast('Failed to advertise', 'error');
            }
        }

        function refreshTailscale() {
            fetchTailscale();
        }

        // Service control
        async function controlService(service, action) {
            try {
                const res = await fetch(`/api/services/${service}/${action}`, {method: 'POST'});
                const data = await res.json();
                if (data.returncode === 0) {
                    showToast(`${service} ${action} successful`, 'success');
                } else {
                    showToast(`${service} ${action} failed: ${data.error}`, 'error');
                }
                fetchSystemInfo();
            } catch (err) {
                showToast('Error controlling service', 'error');
            }
        }

        // Power actions
        async function powerAction(action) {
            if (!confirm(`Are you sure you want to ${action}?`)) return;
            try {
                await fetch(`/api/system/${action}`, {method: 'POST'});
                showToast(`${action} initiated`, 'success');
            } catch (err) {
                showToast('Failed to ' + action, 'error');
            }
        }

        // Logs
        async function fetchLogs() {
            const service = document.getElementById('log-service').value;
            try {
                const res = await fetch(`/api/logs/${service}?lines=50`);
                const data = await res.json();
                document.getElementById('log-content').value = data.logs || '';
            } catch (err) {
                showToast('Error fetching logs', 'error');
            }
        }

        function exportLogs() {
            const service = document.getElementById('log-service').value;
            fetch(`/api/logs/${service}?lines=500`)
                .then(res => res.json())
                .then(data => {
                    const blob = new Blob([JSON.stringify(data.logs)], {type: 'application/json'});
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${service}_logs.json`;
                    a.click();
                })
                .catch(() => showToast('Export failed', 'error'));
        }

        // WebSocket listeners
        socket.on('anomaly', (data) => {
            const alertBox = document.getElementById('live-alerts');
            const newAlert = document.createElement('div');
            newAlert.className = 'p-2 bg-yellow-100 dark:bg-yellow-900/30 border-l-4 border-yellow-500 rounded-r-lg text-sm';
            newAlert.textContent = data.line;
            alertBox.prepend(newAlert);
            if (alertBox.children.length > 10) alertBox.removeChild(alertBox.lastChild);
        });

        // Initial loads
        fetchSystemInfo();
        fetchBandwidth();
        fetchPerfHistory();
        fetchAnomalies();
        fetchWiFi();
        fetchTailscale();
        fetchUfwRules();
        fetchFail2banJails();
        fetchCronJobs();

        // Periodic refresh
        setInterval(fetchSystemInfo, 30000);
        setInterval(fetchAnomalies, 10000);
        setInterval(fetchWiFi, 60000);
        setInterval(fetchPerfHistory, 60000);
        setInterval(fetchUfwRules, 30000);
        setInterval(fetchFail2banJails, 30000);
        setInterval(fetchCronJobs, 30000);
    </script>
</body>
</html>
EOF_HTML

# Set ownership
chown -R $USERNAME:$USERNAME "$APP_DIR"

# Restart service
echo "Restarting dashboard service..."
systemctl restart $SERVICE_NAME

echo "=== Update complete ==="
echo "Check status with: sudo systemctl status $SERVICE_NAME"
echo "If any errors occur, view logs with: sudo journalctl -u $SERVICE_NAME -n 50"
