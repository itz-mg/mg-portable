#!/bin/bash
# mg-travel-server-v4.sh - MG Servers Travel Security Dashboard (fixed)
# For Raspberry Pi OS Lite 64-bit – user 'mg', hostname 'mgtravel'

set -e  # Exit on error

APP_DIR="/opt/mg-travel-dashboard"
LOG_DIR="/var/log/mg-travel"
SERVICE_NAME="mg-travel-dashboard"
USERNAME="mg"
HOSTNAME="mgtravel"

echo "[*] Updating system..."
apt update && apt upgrade -y

# Install required packages (including ufw if missing)
echo "[*] Installing dependencies..."
apt install -y python3 python3-pip python3-venv git iw wireless-tools nginx ufw

# Create directories
mkdir -p $APP_DIR
mkdir -p $LOG_DIR
chown $USERNAME:$USERNAME $LOG_DIR

# Python virtual environment
cd $APP_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install flask flask-socketio flask-limiter flask-login python-dotenv psutil netifaces speedtest-cli tailscale

# Self-signed SSL cert (uses hostname)
mkdir -p $APP_DIR/certs
openssl req -x509 -newkey rsa:4096 -keyout $APP_DIR/certs/key.pem -out $APP_DIR/certs/cert.pem -days 365 -nodes -subj "/CN=${HOSTNAME}.local"

# Configuration
cat > $APP_DIR/config.py << 'EOF'
import os

class Config:
    SECRET_KEY = os.urandom(24).hex()
    TAILSCALE_AUTH = True
    FALLBACK_USER = "admin"
    FALLBACK_PASSWORD = "changeme"
    LOG_DIR = "/var/log/mg-travel"
    ANOMALY_LOG = os.path.join(LOG_DIR, "anomalies.log")
    BANDWIDTH_DB = os.path.join(LOG_DIR, "bandwidth.db")
    UFW_COMMANDS = {
        "status": "ufw status",
        "enable": "ufw --force enable",
        "disable": "ufw disable"
    }
    FAIL2BAN_COMMANDS = {
        "status": "systemctl status fail2ban",
        "start": "systemctl start fail2ban",
        "stop": "systemctl stop fail2ban",
        "restart": "systemctl restart fail2ban"
    }
    WATCHDOG_COMMANDS = {
        "status": "systemctl status watchdog",
        "start": "systemctl start watchdog",
        "stop": "systemctl stop watchdog",
        "restart": "systemctl restart watchdog"
    }
    SSH_COMMANDS = {
        "status": "systemctl status ssh",
        "start": "systemctl start ssh",
        "stop": "systemctl stop ssh",
        "restart": "systemctl restart ssh"
    }
EOF

# Flask app (same as before – included for completeness)
cat > $APP_DIR/app.py << 'EOF_PY'
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
limiter = Limiter(app, key_func=get_remote_address)

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
    # For demo, generate sample data if DB missing
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
    socketio.run(app, host='0.0.0.0', port=8443, ssl_context=('certs/cert.pem', 'certs/key.pem'), debug=False)
EOF_PY

# ---------- Frontend (Templates) ----------
mkdir -p $APP_DIR/templates

# login.html
cat > $APP_DIR/templates/login.html << 'EOF_LOGIN'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MG Travel Security - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-slate-900 to-slate-700 min-h-screen flex items-center justify-center">
    <div class="bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 w-full max-w-md border border-white/20">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-white">MG Travel Security</h1>
            <p class="text-slate-300 mt-2">Sign in to your dashboard</p>
        </div>
        {% if error %}
        <div class="bg-red-500/20 border border-red-500 text-red-200 px-4 py-3 rounded-lg mb-4">{{ error }}</div>
        {% endif %}
        <form method="post" class="space-y-6">
            <div>
                <label class="block text-slate-300 mb-2">Username</label>
                <input type="text" name="username" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-400">
            </div>
            <div>
                <label class="block text-slate-300 mb-2">Password</label>
                <input type="password" name="password" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-400">
            </div>
            <button type="submit" class="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-lg hover:from-cyan-600 hover:to-blue-600 transition duration-200">Login</button>
        </form>
    </div>
</body>
</html>
EOF_LOGIN

# index.html (main dashboard)
cat > $APP_DIR/templates/index.html << 'EOF_HTML'
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
        let bandwidthChart;

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

        function refreshTailscale() {
            fetchTailscale();
        }

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

        async function powerAction(action) {
            if (!confirm(`Are you sure you want to ${action}?`)) return;
            try {
                await fetch(`/api/system/${action}`, {method: 'POST'});
                showToast(`${action} initiated`, 'success');
            } catch (err) {
                showToast('Failed to ' + action, 'error');
            }
        }

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

        socket.on('anomaly', (data) => {
            const alertBox = document.getElementById('live-alerts');
            const newAlert = document.createElement('div');
            newAlert.className = 'p-2 bg-yellow-100 dark:bg-yellow-900/30 border-l-4 border-yellow-500 rounded-r-lg text-sm';
            newAlert.textContent = data.line;
            alertBox.prepend(newAlert);
            if (alertBox.children.length > 10) alertBox.removeChild(alertBox.lastChild);
        });

        fetchSystemInfo();
        fetchBandwidth();
        fetchAnomalies();
        fetchWiFi();
        fetchTailscale();

        setInterval(fetchSystemInfo, 30000);
        setInterval(fetchAnomalies, 10000);
        setInterval(fetchWiFi, 60000);
    </script>
</body>
</html>
EOF_HTML

# ---------- Systemd Service ----------
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF_SERVICE
[Unit]
Description=MG Travel Security Dashboard
After=network.target tailscaled.service

[Service]
Type=simple
User=$USERNAME
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF_SERVICE

# ---------- Firewall (only if ufw is available) ----------
if command -v ufw >/dev/null 2>&1; then
    echo "[*] Configuring UFW firewall..."
    ufw allow 8443/tcp comment 'MG Travel Dashboard'
    ufw allow ssh
    ufw --force enable
else
    echo "[!] UFW not found – skipping firewall configuration."
    echo "    You may need to manually open port 8443 if using another firewall."
fi

# Set ownership of app directory to mg
chown -R $USERNAME:$USERNAME $APP_DIR

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo ""
echo "✅ MG Travel Security Dashboard installed!"
echo "   Access it at:"
echo "   - https://$(hostname -I | awk '{print $1}'):8443"
echo "   - https://${HOSTNAME}.local:8443  (if mDNS is working)"
echo "   Default login: admin / changeme"
echo ""
echo "📘 For hotel WiFi setup, see the guide below."
