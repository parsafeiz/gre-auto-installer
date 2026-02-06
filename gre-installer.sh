#!/bin/bash

CONFIG_DIR="/etc/gre"
SCRIPT="/usr/local/bin/gre.sh"
SERVICE_DIR="/etc/systemd/system"

GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
WHITE="\e[97m"
RESET="\e[0m"

mkdir -p "$CONFIG_DIR"

# ---------- helpers ----------

pause() {
  echo
  read -p "Press Enter to continue..."
}

next_gre() {
  i=1
  while ip link show gre$i &>/dev/null; do
    ((i++))
  done
  echo "gre$i"
}

detect_public_ip() {
  ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}'
}

suggest_private_ip() {
  for i in {100..200}; do
    if ! grep -R "192.168.$i." "$CONFIG_DIR" &>/dev/null; then
      echo "192.168.$i.1/30"
      return
    fi
  done
}

# ---------- gre runtime script ----------

create_gre_script() {
cat > "$SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/gre/$2.conf"
[ ! -f "$CONF" ] && exit 1
source "$CONF"

modprobe ip_gre
sysctl -w net.ipv4.ip_forward=1 >/dev/null

case "$1" in
  start)
    ip tunnel del "$DEV" 2>/dev/null
    ip tunnel add "$DEV" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    ip addr flush dev "$DEV" 2>/dev/null
    ip addr add "$TUN_IP" dev "$DEV"
    ip link set "$DEV" up
    ;;
  stop)
    ip link set "$DEV" down 2>/dev/null
    ip tunnel del "$DEV" 2>/dev/null
    ;;
  restart)
    "$0" stop "$DEV"
    sleep 1
    "$0" start "$DEV"
    ;;
  check)
    ping -c1 -W2 "$PING_TARGET" >/dev/null || {
      echo "$(date) $DEV DOWN, restarting" >> /var/log/gre-watch.log
      "$0" restart "$DEV"
    }
    ;;
esac
EOF
chmod +x "$SCRIPT"
}

# ---------- services ----------

create_service() {
DEV="$1"

cat > "$SERVICE_DIR/gre@$DEV.service" <<EOF
[Unit]
Description=GRE Tunnel $DEV
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT start $DEV
ExecStop=$SCRIPT stop $DEV
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "$SERVICE_DIR/gre-watch@$DEV.service" <<EOF
[Unit]
Description=GRE Watchdog $DEV
After=gre@$DEV.service

[Service]
ExecStart=/bin/bash -c 'while true; do $SCRIPT check $DEV; sleep 10; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF
}

# ---------- actions ----------

create_tunnel() {
  DEV=$(next_gre)
  echo "Creating tunnel: $DEV"

  AUTO_IP=$(detect_public_ip)
  read -p "Local PUBLIC IP [$AUTO_IP]: " LOCAL_IP
  LOCAL_IP=${LOCAL_IP:-$AUTO_IP}

  read -p "Remote PUBLIC IP: " REMOTE_IP

  SUGGEST_IP=$(suggest_private_ip)
  read -p "Tunnel IP [$SUGGEST_IP]: " TUN_IP
  TUN_IP=${TUN_IP:-$SUGGEST_IP}

  read -p "Remote PRIVATE IP for ping: " PING_TARGET

  cat > "$CONFIG_DIR/$DEV.conf" <<EOF
DEV=$DEV
LOCAL_IP=$LOCAL_IP
REMOTE_IP=$REMOTE_IP
TUN_IP=$TUN_IP
PING_TARGET=$PING_TARGET
EOF

  create_gre_script
  create_service "$DEV"

  systemctl daemon-reload
  systemctl enable gre@$DEV gre-watch@$DEV
  systemctl start gre@$DEV gre-watch@$DEV

  echo "Tunnel $DEV created"
  pause
}

delete_tunnel() {
  CONFS=("$CONFIG_DIR"/*.conf)
  [ ! -f "${CONFS[0]}" ] && echo "No tunnels found" && pause && return

  echo
  i=1
  for c in "${CONFS[@]}"; do
    echo "$i) $(basename "$c" .conf)"
    ((i++))
  done
  echo "0) Back"

  read -p "Select: " n
  [ -z "$n" ] || [ "$n" = "0" ] && return

  CONF="${CONFS[$((n-1))]}"
  DEV=$(basename "$CONF" .conf)

  systemctl stop gre-watch@$DEV gre@$DEV 2>/dev/null
  systemctl disable gre-watch@$DEV gre@$DEV 2>/dev/null

  ip tunnel del "$DEV" 2>/dev/null
  rm -f "$CONF"
  rm -f "$SERVICE_DIR/gre@$DEV.service"
  rm -f "$SERVICE_DIR/gre-watch@$DEV.service"

  systemctl daemon-reload
  echo "Tunnel $DEV removed"
  pause
}

status_tunnels() {
  found=0
  for c in "$CONFIG_DIR"/*.conf; do
    [ ! -f "$c" ] && continue
    found=1
    source "$c"
    ping -c1 -W1 "$PING_TARGET" &>/dev/null \
      && echo "$DEV : UP" \
      || echo "$DEV : DOWN"
  done
  [ "$found" -eq 0 ] && echo "No tunnels found"
  pause
}

# ---------- menu ----------

while true; do
  echo
  echo -e "${GREEN}1) Create new tunnel${RESET}"
  echo -e "${RED}2) Delete tunnel${RESET}"
  echo -e "${BLUE}3) Tunnel status${RESET}"
  echo -e "${WHITE}4) Exit${RESET}"
  read -p "Select option: " opt

  case "$opt" in
    1) create_tunnel ;;
    2) delete_tunnel ;;
    3) status_tunnels ;;
    4) exit 0 ;;
  esac
done
