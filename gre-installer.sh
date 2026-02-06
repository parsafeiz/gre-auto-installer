#!/bin/bash

CONFIG_DIR="/etc/gre"
SCRIPT="/usr/local/bin/gre.sh"
SERVICE_DIR="/etc/systemd/system"
LOG_FILE="/var/log/gre-tunnel.log"

GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
WHITE="\e[97m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

# ایجاد دایرکتوری‌ها و فایل لاگ
mkdir -p "$CONFIG_DIR"
touch "$LOG_FILE"

# ---------- نمایش بنر زیبا ----------

show_banner() {
  clear
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                                                              ║"
  echo "║  ██████  ██████  ███████     ████████ ██    ██ ███    ██ ██   ██ ║"
  echo "║ ██    ██ ██   ██ ██             ██    ██    ██ ████   ██ ██  ██ ║║"
  echo "║ ██    ██ ██████  █████          ██    ██    ██ ██ ██  ██ █████   ║"
  echo "║ ██    ██ ██   ██ ██             ██    ██    ██ ██  ██ ██ ██  ██  ║"
  echo "║  ██████  ██   ██ ███████        ██     ██████  ██   ████ ██   ██ ║"
  echo "║                                                                 ║"
  echo "║                                                              ║"
  echo "║                GRE Tunnel Manager v2.0                       ║"
  echo "║                Secure Private Networking                     ║"
  echo "║                Created by: Parsa                             ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "${YELLOW}================================================================================${RESET}"
  echo
}

# ---------- helpers ----------

log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

pause() {
  echo
  read -rp "Press Enter to continue..."
}

next_gre() {
  i=1
  while ip link show "gre$i" &>/dev/null || ip link show "sit$i" &>/dev/null; do
    ((i++))
  done
  echo "gre$i"
}

detect_public_ip() {
  local ip
  # روش‌های مختلف برای تشخیص IP عمومی
  ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || 
       curl -s --max-time 3 icanhazip.com 2>/dev/null || 
       curl -s --max-time 3 ipinfo.io/ip 2>/dev/null)
  
  if [ -z "$ip" ]; then
    # روش fallback
    ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
  fi
  
  echo "$ip"
}

detect_country() {
  local ip="$1"
  local country
  
  country=$(curl -s --max-time 3 "ipapi.co/$ip/country/" 2>/dev/null)
  
  if [ -z "$country" ]; then
    # تشخیص تقریبی بر اساس رنج IP
    if [[ "$ip" =~ ^5\. ]]; then
      echo "IR"
    elif [[ "$ip" =~ ^(185\.|188\.|94\.) ]]; then
      echo "IR"
    elif [[ "$ip" =~ ^(192\.168\.|10\.|172\.) ]]; then
      echo "LOCAL"
    else
      echo "FOREIGN"
    fi
  else
    echo "$country"
  fi
}

suggest_ip_for_country() {
  local country="$1"
  local tunnel_type="$2"  # local یا remote
  
  # بررسی IPهای موجود
  for i in {100..200}; do
    local subnet="192.168.$i.0/30"
    if ! grep -r "192\.168\.$i\." "$CONFIG_DIR" &>/dev/null; then
      if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
        if [ "$tunnel_type" = "local" ]; then
          echo "192.168.$i.1/30"
        else
          echo "192.168.$i.2/30"
        fi
      else
        if [ "$tunnel_type" = "local" ]; then
          echo "192.168.$i.2/30"
        else
          echo "192.168.$i.1/30"
        fi
      fi
      return 0
    fi
  done
  
  # اگر همه پر بودند
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    if [ "$tunnel_type" = "local" ]; then
      echo "192.168.100.1/30"
    else
      echo "192.168.100.2/30"
    fi
  else
    if [ "$tunnel_type" = "local" ]; then
      echo "192.168.100.2/30"
    else
      echo "192.168.100.1/30"
    fi
  fi
}

suggest_ping_target() {
  local tun_ip="$1"
  local country="$2"
  
  # استخراج IP از subnet
  local ip=$(echo "$tun_ip" | cut -d'/' -f1)
  local base=$(echo "$ip" | sed 's/\.[0-9]*$//')
  local last=$(echo "$ip" | awk -F. '{print $4}')
  
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    # اگر ایران هستیم، هدف پینگ IP دوم است
    echo "$base.$((last + 1))"
  else
    # اگر خارج هستیم، هدف پینگ IP اول است
    echo "$base.$((last - 1))"
  fi
}

# ---------- gre runtime script ----------

create_or_update_gre_script() {
  # فقط اگر اسکریپت وجود ندارد، ایجاد کن
  if [ ! -f "$SCRIPT" ]; then
    echo -e "${YELLOW}Creating GRE runtime script...${RESET}"
    
    cat > "$SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/gre/$2.conf"
[ ! -f "$CONF" ] && {
  echo "Error: Config file not found: $CONF"
  exit 1
}

# خواندن متغیرها از config
DEV=""; LOCAL_IP=""; REMOTE_IP=""; TUN_IP=""; PING_TARGET=""; TUNNEL_TYPE=""
while IFS='=' read -r key value; do
  [[ $key =~ ^[[:alpha:]_][[:alnum:]_]*$ ]] || continue
  value=${value#\"}; value=${value%\"}
  declare "$key=$value" 2>/dev/null
done < "$CONF"

# بارگذاری ماژول مناسب
if [ "$TUNNEL_TYPE" = "sit" ]; then
  modprobe ip_tunnel 2>/dev/null
  modprobe sit 2>/dev/null
else
  modprobe ip_gre 2>/dev/null
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

case "$1" in
  start)
    echo "Starting $TUNNEL_TYPE tunnel $DEV"
    # حذف تونل قبلی اگر وجود دارد
    ip tunnel del "$DEV" 2>/dev/null
    
    # ایجاد تونل بر اساس نوع
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      ip tunnel add "$DEV" mode sit local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    else
      ip tunnel add "$DEV" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    fi
    
    # تنظیم IP
    ip addr flush dev "$DEV" 2>/dev/null
    ip addr add "$TUN_IP" dev "$DEV"
    ip link set "$DEV" up
    echo "$TUNNEL_TYPE tunnel $DEV started with IP $TUN_IP"
    ;;
  stop)
    echo "Stopping tunnel $DEV"
    ip link set "$DEV" down 2>/dev/null
    ip tunnel del "$DEV" 2>/dev/null
    echo "Tunnel $DEV stopped"
    ;;
  restart)
    echo "Restarting tunnel $DEV"
    "$0" stop "$DEV"
    sleep 1
    "$0" start "$DEV"
    ;;
  check)
    if ! ping -c1 -W2 "$PING_TARGET" >/dev/null 2>&1; then
      echo "$(date) $DEV DOWN, restarting" >> /var/log/gre-watch.log
      "$0" restart "$DEV"
    fi
    ;;
  status)
    if ip link show "$DEV" &>/dev/null; then
      echo "Tunnel $DEV: UP"
      ip addr show dev "$DEV"
    else
      echo "Tunnel $DEV: DOWN"
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|check|status} <tunnel-name>"
    exit 1
    ;;
esac
EOF
    
    chmod +x "$SCRIPT"
    echo -e "${GREEN}✓ GRE/SIT runtime script created at $SCRIPT${RESET}"
  else
    echo -e "${BLUE}✓ GRE/SIT runtime script already exists${RESET}"
  fi
}

# ---------- services ----------

create_service() {
  local DEV="$1"
  local TUNNEL_TYPE="$2"
  
  echo -e "\n${YELLOW}Creating systemd services for $DEV ($TUNNEL_TYPE)...${RESET}"
  
  # سرویس اصلی تونل
  cat > "$SERVICE_DIR/gre@$DEV.service" <<EOF
[Unit]
Description=$TUNNEL_TYPE Tunnel $DEV
After=network-online.target
Wants=network-online.target
Documentation=man:gre(8)

[Service]
Type=oneshot
ExecStart=$SCRIPT start $DEV
ExecStop=$SCRIPT stop $DEV
RemainAfterExit=yes
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

  # سرویس watchdog برای مانیتورینگ
  cat > "$SERVICE_DIR/gre-watch@$DEV.service" <<EOF
[Unit]
Description=$TUNNEL_TYPE Watchdog $DEV
After=gre@$DEV.service
Requires=gre@$DEV.service
PartOf=gre@$DEV.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do $SCRIPT check $DEV; sleep 10; done'
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  
  echo -e "${GREEN}✓ Systemd services created for $DEV${RESET}"
}

# ---------- actions ----------

create_tunnel() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                    CREATE NEW TUNNEL                        ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  # انتخاب نوع تونل
  echo -e "${YELLOW}Select tunnel type:${RESET}"
  echo "1) GRE Tunnel (Recommended for most cases)"
  echo "2) SIT Tunnel (IPv6 over IPv4)"
  read -rp "Enter choice [1-2, default=1]: " tunnel_choice
  
  case "$tunnel_choice" in
    2) TUNNEL_TYPE="sit" ;;
    *) TUNNEL_TYPE="gre" ;;
  esac
  
  local DEV=$(next_gre)
  echo -e "\n${YELLOW}Detected next available tunnel name: ${GREEN}$DEV${RESET}\n"

  # تشخیص IP محلی و کشور
  local AUTO_IP=$(detect_public_ip)
  local LOCAL_COUNTRY=$(detect_country "$AUTO_IP")
  
  echo -e "${BLUE}Detected your public IP: ${GREEN}$AUTO_IP${RESET}"
  echo -e "${BLUE}Detected country: ${GREEN}$LOCAL_COUNTRY${RESET}"
  read -rp "Local PUBLIC IP [$AUTO_IP]: " LOCAL_IP
  LOCAL_IP=${LOCAL_IP:-$AUTO_IP}
  echo

  read -rp "Remote PUBLIC IP: " REMOTE_IP
  [ -z "$REMOTE_IP" ] && {
    echo -e "\n${RED}✗ Error: Remote IP is required!${RESET}"
    pause
    return 1
  }
  
  # تشخیص کشور سرور مقابل
  local REMOTE_COUNTRY=$(detect_country "$REMOTE_IP")
  echo -e "${BLUE}Remote server country: ${GREEN}$REMOTE_COUNTRY${RESET}"
  echo

  # پیشنهاد IP بر اساس کشور
  local SUGGESTED_LOCAL_IP=$(suggest_ip_for_country "$LOCAL_COUNTRY" "local")
  local SUGGESTED_REMOTE_IP=$(suggest_ip_for_country "$LOCAL_COUNTRY" "remote")
  
  if [ "$LOCAL_COUNTRY" = "IR" ] || [ "$LOCAL_COUNTRY" = "Iran" ]; then
    echo -e "${MAGENTA}Suggested IP configuration (Iran server):${RESET}"
    echo -e "  Your tunnel IP: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    echo -e "  Remote tunnel IP: ${CYAN}$SUGGESTED_REMOTE_IP${RESET}"
  else
    echo -e "${MAGENTA}Suggested IP configuration (Foreign server):${RESET}"
    echo -e "  Your tunnel IP: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    echo -e "  Remote tunnel IP: ${CYAN}$SUGGESTED_REMOTE_IP${RESET}"
  fi
  
  read -rp "Your tunnel IP [$SUGGESTED_LOCAL_IP]: " TUN_IP
  TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
  echo

  # پیشنهاد IP برای پینگ
  local SUGGESTED_PING=$(suggest_ping_target "$TUN_IP" "$LOCAL_COUNTRY")
  
  if [ "$LOCAL_COUNTRY" = "IR" ] || [ "$LOCAL_COUNTRY" = "Iran" ]; then
    echo -e "${BLUE}Suggested ping target (remote private IP): ${GREEN}$SUGGESTED_PING${RESET}"
  else
    echo -e "${BLUE}Suggested ping target (Iran server private IP): ${GREEN}$SUGGESTED_PING${RESET}"
  fi
  
  read -rp "Remote PRIVATE IP for ping [$SUGGESTED_PING]: " PING_TARGET
  PING_TARGET=${PING_TARGET:-$SUGGESTED_PING}
  echo

  # ایجاد فایل config
  echo -e "${YELLOW}Creating configuration file...${RESET}"
  cat > "$CONFIG_DIR/$DEV.conf" <<EOF
# $TUNNEL_TYPE Tunnel Configuration
# Created: $(date)
# Created by: Parsa
# Local Country: $LOCAL_COUNTRY
# Remote Country: $REMOTE_COUNTRY
DEV=$DEV
LOCAL_IP=$LOCAL_IP
REMOTE_IP=$REMOTE_IP
TUN_IP=$TUN_IP
PING_TARGET=$PING_TARGET
TUNNEL_TYPE=$TUNNEL_TYPE
LOCAL_COUNTRY=$LOCAL_COUNTRY
REMOTE_COUNTRY=$REMOTE_COUNTRY
EOF

  echo -e "${GREEN}✓ Configuration saved to $CONFIG_DIR/$DEV.conf${RESET}"

  # ایجاد یا بررسی اسکریپت runtime
  create_or_update_gre_script
  
  # ایجاد سرویس systemd
  create_service "$DEV" "$TUNNEL_TYPE"

  echo -e "\n${YELLOW}Reloading systemd daemon...${RESET}"
  systemctl daemon-reload
  
  echo -e "\n${YELLOW}Enabling and starting services...${RESET}"
  systemctl enable --now "gre@$DEV" > /dev/null 2>&1
  systemctl enable --now "gre-watch@$DEV" > /dev/null 2>&1

  log_message "$TUNNEL_TYPE tunnel $DEV created: LOCAL=$LOCAL_IP ($LOCAL_COUNTRY), REMOTE=$REMOTE_IP ($REMOTE_COUNTRY), TUN=$TUN_IP"
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}✓ $TUNNEL_TYPE Tunnel $DEV created successfully!${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}Config file:${RESET} $CONFIG_DIR/$DEV.conf"
  echo -e "${BLUE}Tunnel type:${RESET} $TUNNEL_TYPE"
  echo -e "${BLUE}Your IP:${RESET} $TUN_IP"
  echo -e "${BLUE}Ping target:${RESET} $PING_TARGET"
  echo -e "${BLUE}Local country:${RESET} $LOCAL_COUNTRY"
  echo -e "${BLUE}Remote country:${RESET} $REMOTE_COUNTRY"
  echo -e "\n${YELLOW}Management commands:${RESET}"
  echo -e "  Check status: ${GREEN}systemctl status gre@$DEV${RESET}"
  echo -e "  Stop tunnel: ${RED}systemctl stop gre@$DEV gre-watch@$DEV${RESET}"
  echo -e "  View logs: ${BLUE}journalctl -u gre@$DEV${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  pause
}

list_all_tunnels() {
  echo -e "\n${YELLOW}Listing all tunnel interfaces...${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  # پیدا کردن همه اینترفیس‌های GRE و SIT
  local found=0
  
  # GRE tunnels
  for iface in $(ip link show | grep -oE 'gre[0-9]+' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IP")
    echo -e "${GREEN}GRE${RESET}  $iface  $status  IP: ${BLUE}$ip${RESET}"
  done
  
  # SIT tunnels
  for iface in $(ip link show | grep -oE 'sit[0-9]+' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IP")
    echo -e "${CYAN}SIT${RESET}   $iface  $status  IP: ${BLUE}$ip${RESET}"
  done
  
  # اینترفیس‌های config شده
  shopt -s nullglob
  for conf in "$CONFIG_DIR"/*.conf; do
    local dev=$(basename "$conf" .conf)
    if ! ip link show "$dev" &>/dev/null; then
      found=1
      # خواندن اطلاعات از config
      local tunnel_type="gre"
      local ip=""
      [ -f "$conf" ] && {
        tunnel_type=$(grep '^TUNNEL_TYPE=' "$conf" | cut -d'=' -f2 || echo "gre")
        ip=$(grep '^TUN_IP=' "$conf" | cut -d'=' -f2 || echo "")
      }
      echo -e "${RED}${tunnel_type^^}${RESET}  $dev  state DOWN  Config IP: ${YELLOW}$ip${RESET}"
    fi
  done
  shopt -u nullglob
  
  if [ "$found" -eq 0 ]; then
    echo -e "${YELLOW}No tunnel interfaces found${RESET}"
  fi
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
}

delete_tunnel() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${RED}                     DELETE TUNNEL                           ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  # لیست همه تونل‌های فعال
  list_all_tunnels
  
  echo -e "\n${YELLOW}Available tunnels (from config files):${RESET}"
  shopt -s nullglob
  local CONFS=("$CONFIG_DIR"/*.conf)
  shopt -u nullglob
  
  if [ ${#CONFS[@]} -eq 0 ]; then
    echo -e "${YELLOW}No tunnel configurations found${RESET}"
    pause
    return
  fi

  echo
  select CONF in "${CONFS[@]}" "Cancel"; do
    [[ -z $CONF ]] && {
      echo -e "${RED}✗ Invalid selection${RESET}"
      continue
    }
    
    [[ "$CONF" == "Cancel" ]] || [[ $REPLY -eq $((${#CONFS[@]}+1)) ]] && {
      echo -e "${YELLOW}Operation cancelled.${RESET}"
      pause
      return
    }
    
    local DEV=$(basename "$CONF" .conf)
    
    # خواندن اطلاعات تونل
    local TUNNEL_TYPE="gre"
    local LOCAL_IP=""
    local REMOTE_IP=""
    [ -f "$CONF" ] && {
      TUNNEL_TYPE=$(grep '^TUNNEL_TYPE=' "$CONF" | cut -d'=' -f2 || echo "gre")
      LOCAL_IP=$(grep '^LOCAL_IP=' "$CONF" | cut -d'=' -f2 || echo "")
      REMOTE_IP=$(grep '^REMOTE_IP=' "$CONF" | cut -d'=' -f2 || echo "")
    }
    
    echo -e "\n${RED}⚠  WARNING: You are about to delete $TUNNEL_TYPE tunnel $DEV${RESET}"
    echo -e "${RED}   Local IP: $LOCAL_IP"
    echo -e "${RED}   Remote IP: $REMOTE_IP${RESET}"
    echo -e "${RED}   This action cannot be undone!${RESET}\n"
    
    read -rp "Type 'DELETE' to confirm: " confirm
    [[ "$confirm" != "DELETE" ]] && {
      echo -e "${YELLOW}Deletion cancelled.${RESET}"
      pause
      return
    }
    
    echo -e "\n${YELLOW}Deleting $TUNNEL_TYPE tunnel $DEV...${RESET}"
    
    # توقف سرویس‌ها
    echo -e "${BLUE}Stopping services...${RESET}"
    systemctl stop "gre-watch@$DEV" 2>/dev/null
    systemctl stop "gre@$DEV" 2>/dev/null
    systemctl disable "gre-watch@$DEV" "gre@$DEV" 2>/dev/null
    
    # حذف تونل
    echo -e "${BLUE}Removing tunnel interface...${RESET}"
    ip link delete "$DEV" 2>/dev/null
    ip tunnel del "$DEV" 2>/dev/null
    
    # حذف فایل‌ها
    echo -e "${BLUE}Removing configuration files...${RESET}"
    rm -f "$CONF"
    rm -f "$SERVICE_DIR/gre@$DEV.service"
    rm -f "$SERVICE_DIR/gre-watch@$DEV.service"
    
    echo -e "${BLUE}Reloading systemd daemon...${RESET}"
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    
    log_message "$TUNNEL_TYPE tunnel $DEV deleted"
    
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}✓ $TUNNEL_TYPE tunnel $DEV removed successfully!${RESET}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
    pause
    break
  done
}

status_tunnels() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}                   TUNNEL STATUS                             ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  # نمایش همه تونل‌های فعال
  list_all_tunnels
  
  echo -e "\n${YELLOW}Detailed status from configuration files:${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  shopt -s nullglob
  local found=0
  local total_up=0
  local total_down=0
  
  for c in "$CONFIG_DIR"/*.conf; do
    found=1
    
    # خواندن config
    local DEV="" PING_TARGET="" TUN_IP="" LOCAL_IP="" REMOTE_IP="" TUNNEL_TYPE="" LOCAL_COUNTRY="" REMOTE_COUNTRY=""
    while IFS='=' read -r key value; do
      case "$key" in
        DEV) DEV="$value" ;;
        PING_TARGET) PING_TARGET="$value" ;;
        TUN_IP) TUN_IP="$value" ;;
        LOCAL_IP) LOCAL_IP="$value" ;;
        REMOTE_IP) REMOTE_IP="$value" ;;
        TUNNEL_TYPE) TUNNEL_TYPE="$value" ;;
        LOCAL_COUNTRY) LOCAL_COUNTRY="$value" ;;
        REMOTE_COUNTRY) REMOTE_COUNTRY="$value" ;;
      esac
    done < "$c"
    
    # تعیین رنگ و نماد بر اساس نوع تونل
    local type_color=$BLUE
    local type_symbol="🌉"
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      type_color=$CYAN
      type_symbol="🔗"
    fi
    
    # بررسی وضعیت
    if ip link show "$DEV" &>/dev/null; then
      if ping -c1 -W1 "$PING_TARGET" &>/dev/null; then
        echo -e "${GREEN}✅${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${GREEN}$DEV${RESET}"
        echo -e "   Status: ${GREEN}UP${RESET} $type_symbol"
        echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
        echo -e "   Local: ${CYAN}$LOCAL_IP${RESET} (${YELLOW}$LOCAL_COUNTRY${RESET})"
        echo -e "   Remote: ${CYAN}$REMOTE_IP${RESET} (${YELLOW}$REMOTE_COUNTRY${RESET})"
        echo -e "   Ping target: ${GREEN}$PING_TARGET ✓${RESET}"
        echo -e "   Config: ${MAGENTA}$(basename "$c")${RESET}\n"
        ((total_up++))
      else
        echo -e "${YELLOW}⚠${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${YELLOW}$DEV${RESET}"
        echo -e "   Status: ${YELLOW}UP (ping failed)${RESET} $type_symbol"
        echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
        echo -e "   Local: ${CYAN}$LOCAL_IP${RESET} (${YELLOW}$LOCAL_COUNTRY${RESET})"
        echo -e "   Remote: ${CYAN}$REMOTE_IP${RESET} (${YELLOW}$REMOTE_COUNTRY${RESET})"
        echo -e "   Ping target: ${RED}$PING_TARGET ✗${RESET}"
        echo -e "   Config: ${MAGENTA}$(basename "$c")${RESET}\n"
        ((total_down++))
      fi
    else
      echo -e "${RED}❌${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${RED}$DEV${RESET}"
      echo -e "   Status: ${RED}DOWN${RESET} $type_symbol"
      echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
      echo -e "   Local: ${CYAN}$LOCAL_IP${RESET} (${YELLOW}$LOCAL_COUNTRY${RESET})"
      echo -e "   Remote: ${CYAN}$REMOTE_IP${RESET} (${YELLOW}$REMOTE_COUNTRY${RESET})"
      echo -e "   Config: ${MAGENTA}$(basename "$c")${RESET}\n"
      ((total_down++))
    fi
  done
  
  [ "$found" -eq 0 ] && echo -e "${YELLOW}No tunnel configurations found${RESET}"
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}Summary:${RESET}"
  echo -e "  Up tunnels: ${GREEN}$total_up${RESET}"
  echo -e "  Down tunnels: ${RED}$total_down${RESET}"
  echo -e "  Total: $((total_up + total_down))"
  
  if [ $total_up -gt 0 ]; then
    echo -e "\n${GREEN}✅ All tunnels are running in background.${RESET}"
    echo -e "${BLUE}You can safely exit this menu.${RESET}"
  fi
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  pause
}

show_help() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                      HELP & GUIDE                          ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  echo -e "${BLUE}📖 What is GRE/SIT Tunnel?${RESET}"
  echo "GRE (Generic Routing Encapsulation): Creates private network"
  echo "SIT (Simple Internet Transition): IPv6 over IPv4 tunneling"
  echo
  
  echo -e "${GREEN}🚀 Features:${RESET}"
  echo "• Automatic IP suggestion based on country"
  echo "• Support for both GRE and SIT tunnels"
  echo "• Iran server: 192.168.x.1, Foreign server: 192.168.x.2"
  echo "• Auto ping target detection"
  echo "• List all GRE/SIT interfaces"
  echo
  
  echo -e "${MAGENTA}🎯 IP Assignment Rules:${RESET}"
  echo "• Iran Server: Gets .1 address (e.g., 192.168.100.1)"
  echo "• Foreign Server: Gets .2 address (e.g., 192.168.100.2)"
  echo "• Ping targets are automatically reversed"
  echo
  
  echo -e "${YELLOW}📋 Manual Management Commands:${RESET}"
  echo -e "  ${CYAN}List all tunnels:${RESET} ip link show | grep -E '(gre|sit)'"
  echo -e "  ${CYAN}Check status:${RESET} systemctl status gre@tunnel_name"
  echo -e "  ${CYAN}Start tunnel:${RESET} systemctl start gre@tunnel_name"
  echo -e "  ${CYAN}Stop tunnel:${RESET} systemctl stop gre@tunnel_name gre-watch@tunnel_name"
  echo -e "  ${CYAN}View logs:${RESET} journalctl -u gre@tunnel_name -f"
  echo -e "  ${CYAN}View config:${RESET} cat /etc/gre/tunnel_name.conf"
  echo
  
  echo -e "${BLUE}💡 Tips:${RESET}"
  echo "• Port 47 (GRE) must be open in firewall"
  echo "• SIT tunnels require IPv6 support"
  echo "• Use country detection for automatic IP assignment"
  echo "• Created by: ${GREEN}Parsa${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  pause
}

# ---------- main menu ----------

while true; do
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                      MAIN MENU                             ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  echo -e "${GREEN}  1) 🚀 Create new tunnel (GRE/SIT)${RESET}"
  echo -e "${RED}  2) 🗑️  Delete tunnel${RESET}"
  echo -e "${BLUE}  3) 📊 Tunnel status${RESET}"
  echo -e "${MAGENTA}  4) 🔍 List all tunnel interfaces${RESET}"
  echo -e "${YELLOW}  5) ❓ Help & Guide${RESET}"
  echo -e "${WHITE}  6) 🚪 Exit menu${RESET}"
  echo
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  read -rp "Select option [1-6]: " opt

  case "$opt" in
    1) create_tunnel ;;
    2) delete_tunnel ;;
    3) status_tunnels ;;
    4) 
      show_banner
      list_all_tunnels
      pause
      ;;
    5) show_help ;;
    6) 
      show_banner
      echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
      echo -e "${GREEN}                     GOODBYE!                              ${RESET}"
      echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
      echo -e "${GREEN}✅ Tunnels continue running in background.${RESET}"
      echo -e "${BLUE}📋 To manage tunnels later:${RESET}"
      echo -e "   Run this script again: ${CYAN}$0${RESET}"
      echo -e "   Or use systemctl commands"
      echo
      echo -e "${MAGENTA}🔗 Created by: Parsa${RESET}"
      echo -e "${MAGENTA}🔗 Stay connected!${RESET}\n"
      echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
      exit 0
      ;;
    *) 
      echo -e "\n${RED}✗ Invalid option! Please select 1-6${RESET}"
      sleep 2
      ;;
  esac
done
