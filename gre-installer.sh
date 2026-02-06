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
  echo "║                GRE/SIT Tunnel Manager v3.0                   ║"
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

# تابع برای پیدا کردن نام تونل بعدی
next_tunnel_name() {
  local tunnel_type="$1"
  local i=1
  
  if [ "$tunnel_type" = "sit" ]; then
    while ip link show "sit$i" &>/dev/null || [ -f "$CONFIG_DIR/sit$i.conf" ]; do
      ((i++))
    done
    echo "sit$i"
  else
    while ip link show "gre$i" &>/dev/null || [ -f "$CONFIG_DIR/gre$i.conf" ]; do
      ((i++))
    done
    echo "gre$i"
  fi
}

# تابع تشخیص IP از اینترفیس سرور
detect_server_ip() {
  local ip=""
  
  # اول: بررسی IP از route به 8.8.8.8
  ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
  
  if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "$ip"
    return 0
  fi
  
  # دوم: بررسی اولین اینترفیس غیر loopback
  ip=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
  
  if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "$ip"
    return 0
  fi
  
  # سوم: بررسی eth0
  ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
  
  if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "$ip"
    return 0
  fi
  
  # چهارم: بررسی ens3, enp0s3, etc
  for iface in $(ip link show 2>/dev/null | grep -oE '^[0-9]+: [a-z0-9]+:' | awk '{print $2}' | tr -d ':' | grep -E '^(eth|enp|ens|eno)' | head -1); do
    ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  
  echo ""
}

# تابع برای تشخیص کشور (ساده شده)
detect_country() {
  local ip="$1"
  
  # اگر IP خصوصی باشد
  if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$ip" =~ ^192\.168\. ]]; then
    echo "PRIVATE"
    return 0
  fi
  
  # تشخیص ساده: اگر IP با 5 شروع شود یا در رنج‌های ایرانی باشد
  if [[ "$ip" =~ ^5\. ]] || [[ "$ip" =~ ^(185\.|188\.|94\.|78\.|37\.27\.|46\.100\.|46\.209\.) ]]; then
    echo "IR"
  else
    echo "FOREIGN"
  fi
}

# تابع برای پیشنهاد IPv4 برای GRE tunnel
suggest_gre_ip() {
  local country="$1"
  local tunnel_type="$2"  # local یا remote
  
  # پیدا کردن subnet آزاد برای GRE
  for i in {100..200}; do
    local config_exists=false
    # اصلاح شده: بررسی فایل‌های config
    if ls "$CONFIG_DIR"/*.conf 1>/dev/null 2>&1; then
      for conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$conf" ] && grep -q "192\.168\.$i\." "$conf" && config_exists=true
      done
    fi
    
    if [ "$config_exists" = false ]; then
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
    echo "192.168.100.1/30"
  else
    echo "192.168.100.2/30"
  fi
}

# تابع برای پیشنهاد IPv6 برای SIT tunnel
suggest_sit_ipv6() {
  local country="$1"
  local tunnel_type="$2"  # local یا remote
  
  # پیدا کردن subnet آزاد برای SIT (IPv6)
  for i in {1..100}; do
    local hex_i=$(printf "%02x" $i)
    local config_exists=false
    
    # اصلاح شده: بررسی فایل‌های config
    if ls "$CONFIG_DIR"/*.conf 1>/dev/null 2>&1; then
      for conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$conf" ] && grep -q "fd00:$hex_i:" "$conf" && config_exists=true
      done
    fi
    
    if [ "$config_exists" = false ]; then
      if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
        if [ "$tunnel_type" = "local" ]; then
          echo "fd00:$hex_i::1/64"
        else
          echo "fd00:$hex_i::2/64"
        fi
      else
        if [ "$tunnel_type" = "local" ]; then
          echo "fd00:$hex_i::2/64"
        else
          echo "fd00:$hex_i::1/64"
        fi
      fi
      return 0
    fi
  done
  
  # اگر همه پر بودند
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    echo "fd00:100::1/64"
  else
    echo "fd00:100::2/64"
  fi
}

# ---------- functions for tunnel management ----------

list_all_tunnels() {
  echo -e "\n${YELLOW}=== Active Tunnel Interfaces ===${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  local found=0
  
  # GRE tunnels
  for iface in $(ip link show 2>/dev/null | grep -oE 'gre[0-9]+:' | tr -d ':' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IP")
    
    if echo "$status" | grep -q "UP"; then
      echo -e "${GREEN}✓ GRE  $iface${RESET}  $status  IP: ${BLUE}$ip${RESET}"
    else
      echo -e "${RED}✗ GRE  $iface${RESET}  $status  IP: ${BLUE}$ip${RESET}"
    fi
  done
  
  # SIT tunnels
  for iface in $(ip link show 2>/dev/null | grep -oE 'sit[0-9]+:' | tr -d ':' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip -6 addr show "$iface" 2>/dev/null | grep -oE 'inet6 [a-f0-9:]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IPv6")
    
    if echo "$status" | grep -q "UP"; then
      echo -e "${CYAN}✓ SIT  $iface${RESET}  $status  IPv6: ${BLUE}$ip${RESET}"
    else
      echo -e "${RED}✗ SIT  $iface${RESET}  $status  IPv6: ${BLUE}$ip${RESET}"
    fi
  done
  
  # نمایش تونل‌های config شده اما غیرفعال
  local conf_files
  conf_files=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null) || true
  
  if [ -n "$conf_files" ]; then
    for conf in $conf_files; do
      local dev=$(basename "$conf" .conf)
      
      # اگر اینترفیس فعال نیست
      if ! ip link show "$dev" &>/dev/null; then
        found=1
        local tunnel_type="gre"
        local ip=""
        local local_ip=""
        local remote_ip=""
        
        # خواندن اطلاعات از config
        while IFS='=' read -r key value; do
          case "$key" in
            TUNNEL_TYPE) tunnel_type="$value" ;;
            TUN_IP) ip="$value" ;;
            LOCAL_IP) local_ip="$value" ;;
            REMOTE_IP) remote_ip="$value" ;;
          esac
        done < "$conf"
        
        if [ "$tunnel_type" = "sit" ]; then
          echo -e "${YELLOW}● SIT  $dev${RESET}  state DOWN  IPv6: ${ip:-"Unknown"}  Remote: ${remote_ip:-"Unknown"}"
        else
          echo -e "${YELLOW}● GRE  $dev${RESET}  state DOWN  IP: ${ip:-"Unknown"}  Remote: ${remote_ip:-"Unknown"}"
        fi
      fi
    done
  fi
  
  if [ $found -eq 0 ]; then
    echo -e "${YELLOW}No tunnel interfaces found${RESET}"
  fi
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
}

delete_tunnel() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${RED}                     DELETE TUNNEL                           ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  # لیست تونل‌های موجود
  list_all_tunnels
  
  echo -e "\n${YELLOW}=== Configured Tunnels ===${RESET}"
  
  # لیست فایل‌های config
  local CONFS=()
  if ls "$CONFIG_DIR"/*.conf 1>/dev/null 2>&1; then
    for conf in "$CONFIG_DIR"/*.conf; do
      CONFS+=("$conf")
    done
  fi
  
  if [ ${#CONFS[@]} -eq 0 ]; then
    echo -e "\n${RED}No tunnel configurations found!${RESET}"
    pause
    return 1
  fi
  
  echo -e "\n${BLUE}Select tunnel to delete:${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  local i=1
  for conf in "${CONFS[@]}"; do
    local dev=$(basename "$conf" .conf)
    local tunnel_type="gre"
    local local_ip=""
    local remote_ip=""
    
    # خواندن اطلاعات از config
    while IFS='=' read -r key value; do
      case "$key" in
        TUNNEL_TYPE) tunnel_type="$value" ;;
        LOCAL_IP) local_ip="$value" ;;
        REMOTE_IP) remote_ip="$value" ;;
      esac
    done < "$conf"
    
    if ip link show "$dev" &>/dev/null; then
      echo -e "${GREEN}$i) $tunnel_type $dev${RESET} - ${local_ip} → ${remote_ip} (ACTIVE)"
    else
      echo -e "${YELLOW}$i) $tunnel_type $dev${RESET} - ${local_ip} → ${remote_ip} (INACTIVE)"
    fi
    ((i++))
  done
  
  echo -e "$i) Cancel"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  read -rp "Select tunnel number [1-$i]: " selection
  
  # بررسی انتخاب
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt $i ]; then
    echo -e "${RED}Invalid selection!${RESET}"
    pause
    return 1
  fi
  
  # اگر Cancel انتخاب شده
  if [ "$selection" -eq $i ]; then
    echo -e "${YELLOW}Operation cancelled.${RESET}"
    pause
    return 0
  fi
  
  local conf="${CONFS[$((selection-1))]}"
  local DEV=$(basename "$conf" .conf)
  
  # خواندن اطلاعات تونل
  local TUNNEL_TYPE="gre"
  local LOCAL_IP=""
  local REMOTE_IP=""
  
  while IFS='=' read -r key value; do
    case "$key" in
      TUNNEL_TYPE) TUNNEL_TYPE="$value" ;;
      LOCAL_IP) LOCAL_IP="$value" ;;
      REMOTE_IP) REMOTE_IP="$value" ;;
    esac
  done < "$conf"
  
  echo -e "\n${RED}⚠  WARNING: You are about to delete $TUNNEL_TYPE tunnel $DEV${RESET}"
  echo -e "${RED}   Local IP: $LOCAL_IP"
  echo -e "${RED}   Remote IP: $REMOTE_IP${RESET}"
  echo -e "${RED}   This action cannot be undone!${RESET}\n"
  
  read -rp "Type 'DELETE' to confirm: " confirm
  if [ "$confirm" != "DELETE" ]; then
    echo -e "${YELLOW}Deletion cancelled.${RESET}"
    pause
    return 0
  fi
  
  echo -e "\n${YELLOW}Deleting $TUNNEL_TYPE tunnel $DEV...${RESET}"
  
  # توقف سرویس‌ها
  echo -e "${BLUE}Stopping services...${RESET}"
  systemctl stop "gre-watch@$DEV" 2>/dev/null
  systemctl stop "gre@$DEV" 2>/dev/null
  systemctl disable "gre-watch@$DEV" "gre@$DEV" 2>/dev/null
  
  # حذف تونل
  echo -e "${BLUE}Removing tunnel interface...${RESET}"
  ip link set "$DEV" down 2>/dev/null
  ip tunnel del "$DEV" 2>/dev/null
  
  # حذف فایل‌ها
  echo -e "${BLUE}Removing configuration files...${RESET}"
  rm -f "$conf"
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
}

status_tunnels() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}                   TUNNEL STATUS                             ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  list_all_tunnels
  
  echo -e "\n${YELLOW}=== Detailed Status ===${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  local found=0
  local total_up=0
  local total_down=0
  
  # لیست فایل‌های config
  local conf_files
  conf_files=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null) || true
  
  if [ -n "$conf_files" ]; then
    for c in $conf_files; do
      found=1
      
      # خواندن config
      local DEV="" PING_TARGET="" TUN_IP="" LOCAL_IP="" REMOTE_IP="" TUNNEL_TYPE="" LOCAL_COUNTRY=""
      while IFS='=' read -r key value; do
        case "$key" in
          DEV) DEV="$value" ;;
          PING_TARGET) PING_TARGET="$value" ;;
          TUN_IP) TUN_IP="$value" ;;
          LOCAL_IP) LOCAL_IP="$value" ;;
          REMOTE_IP) REMOTE_IP="$value" ;;
          TUNNEL_TYPE) TUNNEL_TYPE="$value" ;;
          LOCAL_COUNTRY) LOCAL_COUNTRY="$value" ;;
        esac
      done < "$c"
      
      # تعیین رنگ و نماد
      local type_color=$BLUE
      local type_symbol="🌉"
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        type_color=$CYAN
        type_symbol="🔗"
      fi
      
      # بررسی وضعیت
      if ip link show "$DEV" &>/dev/null; then
        if [ "$TUNNEL_TYPE" = "sit" ]; then
          # برای SIT از ping6 استفاده کن
          if ping6 -c1 -W1 "$PING_TARGET" >/dev/null 2>&1; then
            echo -e "${GREEN}✅${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${GREEN}$DEV${RESET}"
            echo -e "   Status: ${GREEN}UP${RESET} $type_symbol"
            echo -e "   Tunnel IPv6: ${BLUE}$TUN_IP${RESET}"
            echo -e "   Local IPv4: ${CYAN}$LOCAL_IP${RESET}"
            echo -e "   Remote IPv4: ${CYAN}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${GREEN}Success ✓${RESET}"
            ((total_up++))
          else
            echo -e "${YELLOW}⚠${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${YELLOW}$DEV${RESET}"
            echo -e "   Status: ${YELLOW}UP (ping failed)${RESET} $type_symbol"
            echo -e "   Tunnel IPv6: ${BLUE}$TUN_IP${RESET}"
            echo -e "   Local IPv4: ${CYAN}$LOCAL_IP${RESET}"
            echo -e "   Remote IPv4: ${CYAN}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${RED}Failed ✗${RESET}"
            ((total_down++))
          fi
        else
          # برای GRE از ping معمولی استفاده کن
          if ping -c1 -W1 "$PING_TARGET" >/dev/null 2>&1; then
            echo -e "${GREEN}✅${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${GREEN}$DEV${RESET}"
            echo -e "   Status: ${GREEN}UP${RESET} $type_symbol"
            echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
            echo -e "   Local IP: ${CYAN}$LOCAL_IP${RESET}"
            echo -e "   Remote IP: ${CYAN}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${GREEN}Success ✓${RESET}"
            ((total_up++))
          else
            echo -e "${YELLOW}⚠${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${YELLOW}$DEV${RESET}"
            echo -e "   Status: ${YELLOW}UP (ping failed)${RESET} $type_symbol"
            echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
            echo -e "   Local IP: ${CYAN}$LOCAL_IP${RESET}"
            echo -e "   Remote IP: ${CYAN}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${RED}Failed ✗${RESET}"
            ((total_down++))
          fi
        fi
      else
        echo -e "${RED}❌${RESET} ${type_color}$TUNNEL_TYPE${RESET} ${RED}$DEV${RESET}"
        echo -e "   Status: ${RED}DOWN${RESET} $type_symbol"
        echo -e "   Tunnel IP: ${BLUE}$TUN_IP${RESET}"
        echo -e "   Local IP: ${CYAN}$LOCAL_IP${RESET}"
        echo -e "   Remote IP: ${CYAN}$REMOTE_IP${RESET}"
        ((total_down++))
      fi
      echo
    done
  fi
  
  [ "$found" -eq 0 ] && echo -e "${YELLOW}No tunnel configurations found${RESET}"
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BLUE}Summary:${RESET}"
  echo -e "  Up tunnels: ${GREEN}$total_up${RESET}"
  echo -e "  Down tunnels: ${RED}$total_down${RESET}"
  echo -e "  Total: $((total_up + total_down))"
  
  if [ $total_up -gt 0 ]; then
    echo -e "\n${GREEN}✅ Tunnels are running in background.${RESET}"
    echo -e "${BLUE}You can safely exit this menu.${RESET}"
  fi
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  pause
}

# ---------- gre/sit runtime script ----------

create_or_update_gre_script() {
  # فقط اگر اسکریپت وجود ندارد، ایجاد کن
  if [ ! -f "$SCRIPT" ]; then
    echo -e "${YELLOW}Creating GRE/SIT runtime script...${RESET}"
    
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

# فعال کردن IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
if [ "$TUNNEL_TYPE" = "sit" ]; then
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
fi

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
    
    # تنظیم IP بر اساس نوع تونل
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      ip -6 addr add "$TUN_IP" dev "$DEV"
      # فعال کردن IPv6
      sysctl -w net.ipv6.conf.$DEV.disable_ipv6=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.autoconf=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.accept_ra=0 >/dev/null 2>&1
    else
      ip addr add "$TUN_IP" dev "$DEV"
    fi
    
    ip link set "$DEV" up
    echo "$TUNNEL_TYPE tunnel $DEV started"
    ;;
  stop)
    echo "Stopping tunnel $DEV"
    ip link set "$DEV" down 2>/dev/null
    ip tunnel del "$DEV" 2>/dev/null
    ;;
  restart)
    "$0" stop "$DEV"
    sleep 1
    "$0" start "$DEV"
    ;;
  check)
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      if ! ping6 -c1 -W2 "$PING_TARGET" >/dev/null 2>&1; then
        echo "$(date) $DEV DOWN, restarting" >> /var/log/gre-watch.log
        "$0" restart "$DEV"
      fi
    else
      if ! ping -c1 -W2 "$PING_TARGET" >/dev/null 2>&1; then
        echo "$(date) $DEV DOWN, restarting" >> /var/log/gre-watch.log
        "$0" restart "$DEV"
      fi
    fi
    ;;
  status)
    if ip link show "$DEV" &>/dev/null; then
      echo "Tunnel $DEV: UP"
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        ip -6 addr show dev "$DEV" 2>/dev/null
      else
        ip addr show dev "$DEV" 2>/dev/null
      fi
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

[Service]
Type=oneshot
ExecStart=$SCRIPT start $DEV
ExecStop=$SCRIPT stop $DEV
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  # سرویس watchdog
  cat > "$SERVICE_DIR/gre-watch@$DEV.service" <<EOF
[Unit]
Description=$TUNNEL_TYPE Watchdog $DEV
After=gre@$DEV.service
Requires=gre@$DEV.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do $SCRIPT check $DEV; sleep 10; done'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  
  echo -e "${GREEN}✓ Systemd services created for $DEV${RESET}"
}

# ---------- create tunnel ----------

create_tunnel() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                    CREATE NEW TUNNEL                        ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  # انتخاب نوع تونل
  echo -e "${YELLOW}Select tunnel type:${RESET}"
  echo "1) GRE Tunnel - IPv4 over IPv4 (Recommended)"
  echo "2) SIT Tunnel - IPv6 over IPv4"
  read -rp "Enter choice [1-2, default=1]: " tunnel_choice
  
  case "$tunnel_choice" in
    2) TUNNEL_TYPE="sit" ;;
    *) TUNNEL_TYPE="gre" ;;
  esac
  
  local DEV=$(next_tunnel_name "$TUNNEL_TYPE")
  echo -e "\n${YELLOW}Tunnel name: ${GREEN}$DEV${RESET}\n"

  # تشخیص IP سرور
  echo -e "${BLUE}Detecting server IP address...${RESET}"
  local SERVER_IP=$(detect_server_ip)
  
  if [ -n "$SERVER_IP" ]; then
    echo -e "${GREEN}✓ Detected server IP: $SERVER_IP${RESET}"
    read -rp "Local server IP [$SERVER_IP]: " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-$SERVER_IP}
  else
    echo -e "${RED}✗ Could not detect server IP${RESET}"
    read -rp "Local server IP: " LOCAL_IP
  fi
  
  echo

  # دریافت IP سرور مقابل
  read -rp "Remote server IP: " REMOTE_IP
  echo

  # پیشنهاد IP بر اساس نوع تونل
  local LOCAL_COUNTRY=$(detect_country "$LOCAL_IP")
  
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    SUGGESTED_LOCAL_IP=$(suggest_sit_ipv6 "$LOCAL_COUNTRY" "local")
    echo -e "${MAGENTA}Suggested IPv6 address: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    
    read -rp "Your tunnel IPv6 [$SUGGESTED_LOCAL_IP]: " TUN_IP
    TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
    
    # پیشنهاد IP برای پینگ
    local base_ip=$(echo "$TUN_IP" | sed 's/::[0-9a-f]*\/.*//')
    if [[ "$TUN_IP" =~ ::1/ ]]; then
      SUGGESTED_PING="${base_ip}::2"
    else
      SUGGESTED_PING="${base_ip}::1"
    fi
  else
    SUGGESTED_LOCAL_IP=$(suggest_gre_ip "$LOCAL_COUNTRY" "local")
    echo -e "${MAGENTA}Suggested IPv4 address: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    
    read -rp "Your tunnel IPv4 [$SUGGESTED_LOCAL_IP]: " TUN_IP
    TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
    
    # پیشنهاد IP برای پینگ
    local base_ip=$(echo "$TUN_IP" | sed 's/\.[0-9]*\/.*//')
    local last_digit=$(echo "$TUN_IP" | grep -oE '[0-9]+/' | head -1 | tr -d '/')
    if [ "$last_digit" = "1" ]; then
      SUGGESTED_PING="${base_ip}.2"
    else
      SUGGESTED_PING="${base_ip}.1"
    fi
  fi
  
  echo -e "${BLUE}Suggested ping target: ${GREEN}$SUGGESTED_PING${RESET}"
  read -rp "Ping target IP [$SUGGESTED_PING]: " PING_TARGET
  PING_TARGET=${PING_TARGET:-$SUGGESTED_PING}
  echo

  # ایجاد فایل config
  echo -e "${YELLOW}Creating configuration file...${RESET}"
  cat > "$CONFIG_DIR/$DEV.conf" <<EOF
# $TUNNEL_TYPE Tunnel Configuration
# Created: $(date)
DEV=$DEV
LOCAL_IP=$LOCAL_IP
REMOTE_IP=$REMOTE_IP
TUN_IP=$TUN_IP
PING_TARGET=$PING_TARGET
TUNNEL_TYPE=$TUNNEL_TYPE
EOF

  echo -e "${GREEN}✓ Configuration saved to $CONFIG_DIR/$DEV.conf${RESET}"

  # ایجاد یا بررسی اسکریپت runtime
  create_or_update_gre_script
  
  # ایجاد سرویس systemd
  create_service "$DEV" "$TUNNEL_TYPE"

  echo -e "\n${YELLOW}Starting tunnel...${RESET}"
  systemctl daemon-reload
  systemctl enable --now "gre@$DEV" >/dev/null 2>&1
  systemctl enable --now "gre-watch@$DEV" >/dev/null 2>&1

  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}✓ $TUNNEL_TYPE tunnel $DEV created successfully!${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  
  echo -e "Check status: ${GREEN}systemctl status gre@$DEV${RESET}"
  echo -e "Test connection: ${GREEN}ping $PING_TARGET${RESET}"
  
  pause
}

# ---------- main menu ----------

while true; do
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                      MAIN MENU                             ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  echo -e "${GREEN}  1) 🚀 Create new tunnel${RESET}"
  echo -e "${RED}  2) 🗑️  Delete tunnel${RESET}"
  echo -e "${BLUE}  3) 📊 Tunnel status${RESET}"
  echo -e "${MAGENTA}  4) 🔍 List all tunnels${RESET}"
  echo -e "${YELLOW}  5) 🚪 Exit${RESET}"
  echo
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  read -rp "Select option [1-5]: " opt

  case "$opt" in
    1) create_tunnel ;;
    2) delete_tunnel ;;
    3) status_tunnels ;;
    4) 
      show_banner
      list_all_tunnels
      pause
      ;;
    5) 
      echo -e "\n${GREEN}Goodbye!${RESET}"
      exit 0
      ;;
    *) 
      echo -e "\n${RED}Invalid option!${RESET}"
      sleep 1
      ;;
  esac
done
