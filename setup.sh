#!/bin/bash
# MG Servers Full Setup Script
# Raspberry Pi Zero 2W – Portable SMB + Hotspot + Backup + Tailscale

echo "🚀 Starting MG Servers Full Installation..."

# 1️⃣ Update & upgrade
sudo apt update -y
sudo apt upgrade -y

# 2️⃣ Install required packages
echo "📦 Installing required packages..."
sudo apt install -y samba avahi-daemon hostapd dnsmasq openssh-server curl

# 3️⃣ Create folder structure
echo "📁 Creating folder structure..."
sudo mkdir -p /mgservers/shared
sudo mkdir -p /mgservers/backups/android
sudo mkdir -p /mgservers/backups/iphone
sudo mkdir -p /mgservers/private
sudo chmod -R 775 /mgservers
sudo chown -R pi:pi /mgservers

# 4️⃣ Performance tweaks
echo "⚡ Optimizing system performance..."
echo "net.core.rmem_max=16777216" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=16777216" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 5️⃣ Configure hotspot
echo "📡 Configuring Hotspot..."
sudo systemctl stop hostapd
sudo systemctl stop dnsmasq

# Hostapd config
sudo bash -c 'cat > /etc/hostapd/hostapd.conf <<EOF
interface=wlan0
driver=nl80211
ssid=MG-Servers
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=manolisgserver123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF'

sudo sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# Dnsmasq config
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo bash -c 'cat > /etc/dnsmasq.conf <<EOF
interface=wlan0
dhcp-range=192.168.4.10,192.168.4.100,255.255.255.0,24h
EOF'

# dhcpcd static IP
sudo sed -i '/interface wlan0/,$d' /etc/dhcpcd.conf
sudo bash -c 'cat >> /etc/dhcpcd.conf <<EOF

interface wlan0
static ip_address=192.168.4.1/24
nohook wpa_supplicant
EOF'

# 6️⃣ Configure Samba
echo "🔐 Configuring Samba..."
sudo bash -c 'cat >> /etc/samba/smb.conf <<EOF

[MGServers]
path = /mgservers/shared
browseable = yes
writeable = yes
valid users = pi
create mask = 0775
directory mask = 0775
socket options = TCP_NODELAY SO_RCVBUF=65536 SO_SNDBUF=65536

[Backups]
path = /mgservers/backups
browseable = yes
writeable = yes
valid users = pi

[Private]
path = /mgservers/private
browseable = no
writeable = yes
valid users = pi
EOF'

echo "👉 Set your Samba password (remember this!)"
sudo smbpasswd -a pi
sudo systemctl restart smbd

# 7️⃣ Enable all services
echo "🌍 Enabling services..."
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
sudo systemctl enable smbd
sudo systemctl enable avahi-daemon
sudo systemctl enable ssh

# 8️⃣ Install Tailscale (optional remote access)
echo "🔗 Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh

# 9️⃣ Finish
echo ""
echo "✅ MG Servers Installation Complete!"
echo ""
echo "After reboot:"
echo "1️⃣ Connect to WiFi: MG Servers"
echo "2️⃣ SMB address: smb://192.168.4.1 or smb://mgservers.local"
echo "3️⃣ Android: use FolderSync / Solid Explorer"
echo "4️⃣ iPhone: use Files app or PhotoSync"
echo ""
echo "Rebooting in 5 seconds..."
sleep 5
sudo reboot
