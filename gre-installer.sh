#!/usr/bin/env bash
# =====================================================
# GRE Tunnel Auto Installer
# Created by Parsa
# Compatible with: bash <(curl ...)
# =====================================================
set -e

# ------------------------------
# Root check
# ------------------------------
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root"
  exit 1
fi

# ------------------------------
# Paths
# ------------------------------
GRE_SCRIPT="/usr/local/bin/gre.sh"
GRE_SERVICE="/etc/systemd/system/gre.service"
GRE_WATCH_SERVICE="/etc/systemd/system/gre-watch.service"
LOG_FILE="/var/log/gre-watch.log"
CIDR_SUFFIX="/30"

# ------------------------------
# Functions
# ------------------------------

get_public_ip() {
  curl -s https://api.ipify.org || curl -s https://ifconfig.me
}

valid_ip() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<< "$ip"
  for i in $a $b $c $d; do
    (( i >= 0 && i <= 255 )) || return 1
  done
  return 0
}

# Load configuration if exists
CONFIG_FILE="./gre.conf"
if [ -f "$CONFIG_FILE" ]; then
  echo "📄 Loading configuration from $CONFIG_FILE"
  source "$CONFIG_FILE"
else
  echo "⚠️ Configuration file gre.conf not found. Using interactive mode."
  # Interactive mode
  read -p "Local IP (public) [$(get_public_ip)]: " LOCAL_IP
  LOCAL_IP=${LOCAL_IP:-$(get_public_ip)}

  read -p "Remote IP: " REMOTE_IP
  while ! valid_ip "$REMOTE_IP"; do
    echo "Invalid IP!"
    read -p "Remote IP: " REMOTE_IP
  done

  read -p "Tunnel Private IP (e.g. 10.0.0.1): " PRIVATE_IP
  while ! valid_ip "$PRIVATE_IP"; do
    echo "Invalid IP!"
    read -p "Tunnel Private IP: " PRIVATE_IP
  done

  read -p "Ping target IP [8.8.8.8]: " PING_TARGET
  PING_TARGET=${PING_TARGET:-8.8.8.8}

  read -p "GRE Interface Name [gre1]: " DEV
  DEV=${DEV:-gre1}
fi

TUN_IP="${PRIVATE_IP}${CIDR_SUFFIX}"

# ------------------------------
# Create GRE script
# ------------------------------
create_gre_script() {
cat <<EOF > "$GRE_SCRIPT"
#!/usr/bin/env bash
LOCAL_IP="$LOCAL_IP"
REMOTE_IP="$REMOTE_IP"
TUN_IP="$TUN_IP"
DEV="$DEV"
PING_TARGET="$PING_TARGET"
LOG_FILE="$LOG_FILE"

case "\$1" in
  start)
    ip tunnel del \$DEV 2>/dev/null || true
    ip tunnel add \$DEV mode gre local \$LOCAL_IP remote \$REMOTE_IP ttl 255
    ip addr add \$TUN_IP dev \$DEV
    ip link set \$DEV up
    ;;
  stop)
    ip link set \$DEV down 2>/dev/null || true
    ip tunnel del \$DEV 2>/dev/null || true
    ;;
  restart)
    \$0 stop
    sleep 1
    \$0 start
    ;;
  check)
    if ! ping -c 3 -W 2 \$PING_TARGET >/dev/null; then
      echo "\$(date) GRE down, restarting..." >> \$LOG_FILE
      \$0 restart
    fi
    ;;
  *)
    echo "Usage: \$0 {start|stop|restart|check}"
    exit 1
    ;;
esac
EOF

chmod +x "$GRE_SCRIPT"
}

# ------------------------------
# Create systemd services
# ------------------------------
create_systemd_services() {
# GRE Tunnel Service
cat <<EOF > "$GRE_SERVICE"
[Unit]
Description=GRE Tunnel Service
After=network.target

[Service]
Type=oneshot
ExecStart=$GRE_SCRIPT start
ExecStop=$GRE_SCRIPT stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# GRE Watchdog Service
cat <<EOF > "$GRE_WATCH_SERVICE"
[Unit]
Description=GRE Ping Watchdog
After=gre.service

[Service]
ExecStart=/bin/bash -c 'while true; do $GRE_SCRIPT check; sleep 10; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gre gre-watch
systemctl start gre gre-watch
}

# ------------------------------
# Remove GRE tunnel
# ------------------------------
remove_gre() {
  systemctl stop gre gre-watch 2>/dev/null || true
  systemctl disable gre gre-watch 2>/dev/null || true

  rm -f "$GRE_SCRIPT" "$GRE_SERVICE" "$GRE_WATCH_SERVICE" "$LOG_FILE"

  systemctl daemon-reload

  ip tunnel show | awk '/gre/ {print $1}' | while read d; do
    ip tunnel del "$d" 2>/dev/null || true
  done

  echo "✅ GRE tunnel and services removed."
}

# ------------------------------
# Main menu
# ------------------------------
echo "=============================="
echo "1) Create GRE tunnel and services"
echo "2) Remove GRE tunnel and services"
echo "=============================="

read -p "Select option [1-2]: " OPTION

case "$OPTION" in
  1)
    create_gre_script
    create_systemd_services
    echo "✅ GRE tunnel created successfully."
    ;;
  2)
    remove_gre
    ;;
  *)
    echo "❌ Invalid option"
    exit 1
    ;;
esac
