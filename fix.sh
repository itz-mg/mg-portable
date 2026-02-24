#!/usr/bin/env bash
set -euo pipefail

echo "==> Fixing mgtravel service file (StartLimitIntervalSec placement)..."
cat > /etc/systemd/system/mgtravel.service << 'SVCEOF'
[Unit]
Description=MG Travel — SD Backup Station (MG Servers)
Documentation=https://mgservers.io
After=network.target
Wants=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=mgtravel
Group=mgtravel
WorkingDirectory=/opt/mgtravel
Environment=PYTHONUNBUFFERED=1
Environment=FLASK_ENV=production
ExecStart=/opt/mgtravel/venv/bin/gunicorn \
    --worker-class eventlet \
    --workers 2 \
    --bind 127.0.0.1:5000 \
    --timeout 120 \
    --keep-alive 5 \
    --max-requests 500 \
    --max-requests-jitter 50 \
    --log-level warning \
    --access-logfile /var/log/mgtravel/access.log \
    --error-logfile  /var/log/mgtravel/error.log \
    app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/opt/mgtravel/backups /opt/mgtravel/logs /var/log/mgtravel /mnt
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_ADMIN
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_ADMIN

StandardOutput=journal
StandardError=journal
SyslogIdentifier=mgtravel

[Install]
WantedBy=multi-user.target
SVCEOF

echo "==> Fixing venv execute permissions..."
find /opt/mgtravel/venv/bin -type f -exec file {} \; | grep -l "script\|executable\|ELF" 2>/dev/null || true
chmod 755 /opt/mgtravel/venv/bin/gunicorn
chmod 755 /opt/mgtravel/venv/bin/python3
chmod 755 /opt/mgtravel/venv/bin/python
chmod 755 /opt/mgtravel/venv/bin/pip
find /opt/mgtravel/venv/bin -type f | while read f; do
    head -c 4 "$f" 2>/dev/null | grep -q $'\x7fELF\|#!' && chmod 755 "$f" || true
done

echo "==> Fixing sysctl.conf..."
if [[ ! -f /etc/sysctl.conf ]]; then
    echo "vm.swappiness=10" > /etc/sysctl.conf
else
    grep -q "vm.swappiness" /etc/sysctl.conf || echo "vm.swappiness=10" >> /etc/sysctl.conf
fi
sysctl -w vm.swappiness=10 2>/dev/null || true

echo "==> Reloading systemd and starting mgtravel..."
systemctl daemon-reload
systemctl restart mgtravel

sleep 2
if systemctl is-active --quiet mgtravel; then
    echo "✔  mgtravel is running!"
    systemctl status mgtravel --no-pager -l
else
    echo "✖  Still failing — showing logs:"
    journalctl -u mgtravel -n 30 --no-pager
fi
