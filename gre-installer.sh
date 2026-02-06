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
  echo "║                GRE/SIT Tunnel Manager v2.0                   ║"
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
  local ip=""
  
  # لیست چندین سرویس مختلف برای تشخیص IP
  local services=(
    "https://api.ipify.org"
    "https://icanhazip.com"
    "https://ifconfig.me"
    "https://ipecho.net/plain"
    "https://checkip.amazonaws.com"
    "https://ident.me"
  )
  
  # تلاش برای دریافت IP از هر سرویس
  for service in "${services[@]}"; do
    ip=$(curl -s --max-time 3 "$service" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    
    # بررسی معتبر بودن IP
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      # بررسی اینکه octet‌ها در محدوده معتبر باشند
      local valid=1
      IFS='.' read -r -a octets <<< "$ip"
      for octet in "${octets[@]}"; do
        if [[ $octet -lt 0 || $octet -gt 255 ]]; then
          valid=0
          break
        fi
      done
      
      if [[ $valid -eq 1 ]]; then
        echo "$ip"
        return 0
      fi
    fi
  done
  
  # روش fallback - استفاده از route
  ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
  
  if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "$ip"
  else
    echo ""
  fi
}

detect_country() {
  local ip="$1"
  local country
  
  # اگر IP خصوصی باشد
  if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$ip" =~ ^192\.168\. ]]; then
    echo "PRIVATE"
    return 0
  fi
  
  # تلاش برای تشخیص کشور
  country=$(curl -s --max-time 3 "ipapi.co/$ip/country/" 2>/dev/null)
  
  if [ -n "$country" ] && [ "$country" != "null" ]; then
    echo "$country"
    return 0
  fi
  
  # تشخیص تقریبی بر اساس رنج IP ایرانی
  if [[ "$ip" =~ ^5\. ]] || [[ "$ip" =~ ^(185\.|188\.|94\.|78\.|2\.144\.|2\.176\.|37\.27\.|37\.156\.|46\.100\.|46\.209\.|46\.224\.|77\.104\.|78\.157\.|79\.127\.|79\.175\.|80\.75\.|80\.191\.|81\.12\.|81\.16\.|81\.31\.|82\.99\.|83\.123\.|84\.241\.|85\.133\.|85\.185\.|85\.204\.|86\.104\.|86\.57\.|87\.107\.|87\.247\.|88\.150\.|89\.32\.|89\.43\.|89\.144\.|89\.165\.|91\.92\.|91\.98\.|92\.50\.|93\.110\.|93\.117\.|93\.126\.|94\.74\.|94\.101\.|94\.183\.|94\.184\.|95\.38\.|95\.64\.|95\.80\.|95\.82\.|109\.72\.|109\.109\.|109\.125\.|109\.162\.|128\.65\.|128\.140\.|130\.185\.|130\.255\.|151\.232\.|151\.233\.|151\.238\.|151\.239\.|151\.240\.|151\.241\.|151\.242\.|151\.243\.|151\.244\.|151\.245\.|151\.246\.|151\.247\.|151\.248\.|151\.249\.|151\.250\.|151\.251\.|158\.58\.|159\.20\.|164\.138\.|176\.12\.|176\.102\.|178\.131\.|178\.157\.|178\.173\.|178\.216\.|178\.239\.|178\.252\.|185\.4\.|185\.5\.|185\.10\.|185\.12\.|185\.13\.|185\.14\.|185\.15\.|185\.16\.|185\.17\.|185\.18\.|185\.19\.|185\.20\.|185\.21\.|185\.22\.|185\.23\.|185\.24\.|185\.25\.|185\.26\.|185\.27\.|185\.28\.|185\.29\.|185\.30\.|185\.31\.|185\.32\.|185\.33\.|185\.34\.|185\.35\.|185\.36\.|185\.37\.|185\.38\.|185\.39\.|185\.40\.|185\.41\.|185\.42\.|185\.43\.|185\.44\.|185\.45\.|185\.46\.|185\.47\.|185\.48\.|185\.49\.|185\.50\.|185\.51\.|185\.52\.|185\.53\.|185\.54\.|185\.55\.|185\.56\.|185\.57\.|185\.58\.|185\.59\.|185\.60\.|185\.61\.|185\.62\.|185\.63\.|185\.64\.|185\.65\.|185\.66\.|185\.67\.|185\.68\.|185\.69\.|185\.70\.|185\.71\.|185\.72\.|185\.73\.|185\.74\.|185\.75\.|185\.76\.|185\.77\.|185\.78\.|185\.79\.|185\.80\.|185\.81\.|185\.82\.|185\.83\.|185\.84\.|185\.85\.|185\.86\.|185\.87\.|185\.88\.|185\.89\.|185\.90\.|185\.91\.|185\.92\.|185\.93\.|185\.94\.|185\.95\.|185\.96\.|185\.97\.|185\.98\.|185\.99\.|185\.100\.|185\.101\.|185\.102\.|185\.103\.|185\.104\.|185\.105\.|185\.106\.|185\.107\.|185\.108\.|185\.109\.|185\.110\.|185\.111\.|185\.112\.|185\.113\.|185\.114\.|185\.115\.|185\.116\.|185\.117\.|185\.118\.|185\.119\.|185\.120\.|185\.121\.|185\.122\.|185\.123\.|185\.124\.|185\.125\.|185\.126\.|185\.127\.|185\.128\.|185\.129\.|185\.130\.|185\.131\.|185\.132\.|185\.133\.|185\.134\.|185\.135\.|185\.136\.|185\.137\.|185\.138\.|185\.139\.|185\.140\.|185\.141\.|185\.142\.|185\.143\.|185\.144\.|185\.145\.|185\.146\.|185\.147\.|185\.148\.|185\.149\.|185\.150\.|185\.151\.|185\.152\.|185\.153\.|185\.154\.|185\.155\.|185\.156\.|185\.157\.|185\.158\.|185\.159\.|185\.160\.|185\.161\.|185\.162\.|185\.163\.|185\.164\.|185\.165\.|185\.166\.|185\.167\.|185\.168\.|185\.169\.|185\.170\.|185\.171\.|185\.172\.|185\.173\.|185\.174\.|185\.175\.|185\.176\.|185\.177\.|185\.178\.|185\.179\.|185\.180\.|185\.181\.|185\.182\.|185\.183\.|185\.184\.|185\.185\.|185\.186\.|185\.187\.|185\.188\.|185\.189\.|185\.190\.|185\.191\.|185\.192\.|185\.193\.|185\.194\.|185\.195\.|185\.196\.|185\.197\.|185\.198\.|185\.199\.|185\.200\.|185\.201\.|185\.202\.|185\.203\.|185\.204\.|185\.205\.|185\.206\.|185\.207\.|185\.208\.|185\.209\.|185\.210\.|185\.211\.|185\.212\.|185\.213\.|185\.214\.|185\.215\.|185\.216\.|185\.217\.|185\.218\.|185\.219\.|185\.220\.|185\.221\.|185\.222\.|185\.223\.|185\.224\.|185\.225\.|185\.226\.|185\.227\.|185\.228\.|185\.229\.|185\.230\.|185\.231\.|185\.232\.|185\.233\.|185\.234\.|185\.235\.|185\.236\.|185\.237\.|185\.238\.|185\.239\.|185\.240\.|185\.241\.|185\.242\.|185\.243\.|185\.244\.|185\.245\.|185\.246\.|185\.247\.|185\.248\.|185\.249\.|185\.250\.|185\.251\.|185\.252\.|185\.253\.|185\.254\.|185\.255\.) ]]; then
    echo "IR"
  else
    echo "FOREIGN"
  fi
}

suggest_ip_for_country() {
  local country="$1"
  local tunnel_type="$2"  # local یا remote
  local tunnel_protocol="$3"  # gre یا sit
  
  # پیدا کردن subnet آزاد
  for i in {100..200}; do
    if ! grep -r "192\.168\.$i\." "$CONFIG_DIR" &>/dev/null; then
      if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
        if [ "$tunnel_protocol" = "sit" ]; then
          # برای SIT tunnel می‌توان از رنج متفاوتی استفاده کرد
          if [ "$tunnel_type" = "local" ]; then
            echo "192.168.$i.1/30"
          else
            echo "192.168.$i.2/30"
          fi
        else
          # برای GRE tunnel
          if [ "$tunnel_type" = "local" ]; then
            echo "192.168.$i.1/30"
          else
            echo "192.168.$i.2/30"
          fi
        fi
      else
        if [ "$tunnel_protocol" = "sit" ]; then
          if [ "$tunnel_type" = "local" ]; then
            echo "192.168.$i.2/30"
          else
            echo "192.168.$i.1/30"
          fi
        else
          if [ "$tunnel_type" = "local" ]; then
            echo "192.168.$i.2/30"
          else
            echo "192.168.$i.1/30"
          fi
        fi
      fi
      return 0
    fi
  done
  
  # اگر همه پر بودند
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    if [ "$tunnel_protocol" = "sit" ]; then
      echo "192.168.150.1/30"  # رنج متفاوت برای SIT
    else
      echo "192.168.100.1/30"
    fi
  else
    if [ "$tunnel_protocol" = "sit" ]; then
      echo "192.168.150.2/30"  # رنج متفاوت برای SIT
    else
      echo "192.168.100.2/30"
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
  echo "Loaded SIT tunnel modules"
else
  modprobe ip_gre 2>/dev/null
  echo "Loaded GRE tunnel modules"
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

case "$1" in
  start)
    echo "Starting $TUNNEL_TYPE tunnel $DEV"
    # حذف تونل قبلی اگر وجود دارد
    ip tunnel del "$DEV" 2>/dev/null
    
    # ایجاد تونل بر اساس نوع
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      echo "Creating SIT tunnel: ip tunnel add $DEV mode sit local $LOCAL_IP remote $REMOTE_IP ttl 255"
      ip tunnel add "$DEV" mode sit local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    else
      echo "Creating GRE tunnel: ip tunnel add $DEV mode gre local $LOCAL_IP remote $REMOTE_IP ttl 255"
      ip tunnel add "$DEV" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    fi
    
    # تنظیم IP
    ip addr flush dev "$DEV" 2>/dev/null
    echo "Setting IP: ip addr add $TUN_IP dev $DEV"
    ip addr add "$TUN_IP" dev "$DEV"
    ip link set "$DEV" up
    
    # برای SIT tunnel، تنظیمات اضافی
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      # فعال کردن IPv6 روی اینترفیس
      sysctl -w net.ipv6.conf.$DEV.disable_ipv6=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.autoconf=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.accept_ra=0 >/dev/null 2>&1
    fi
    
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
      
      # اطلاعات اضافی برای SIT
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        echo "IPv6 configuration:"
        ip -6 addr show dev "$DEV" 2>/dev/null || echo "No IPv6 address configured"
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
  echo "1) GRE Tunnel (Recommended for most cases) - IPv4 over IPv4"
  echo "2) SIT Tunnel (IPv6 over IPv4) - For IPv6 connectivity"
  read -rp "Enter choice [1-2, default=1]: " tunnel_choice
  
  case "$tunnel_choice" in
    2) 
      TUNNEL_TYPE="sit"
      echo -e "${CYAN}Selected: SIT Tunnel (IPv6 over IPv4)${RESET}"
      echo -e "${YELLOW}Note: SIT tunnels encapsulate IPv6 traffic over IPv4${RESET}"
      ;;
    *) 
      TUNNEL_TYPE="gre"
      echo -e "${CYAN}Selected: GRE Tunnel (IPv4 over IPv4)${RESET}"
      ;;
  esac
  
  local DEV
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    # برای SIT، نام‌های sitX را بررسی کن
    i=1
    while ip link show "sit$i" &>/dev/null; do
      ((i++))
    done
    DEV="sit$i"
  else
    # برای GRE، نام‌های greX را بررسی کن
    i=1
    while ip link show "gre$i" &>/dev/null; do
      ((i++))
    done
    DEV="gre$i"
  fi
  
  echo -e "\n${YELLOW}Next available tunnel name: ${GREEN}$DEV${RESET}\n"

  # تشخیص IP محلی
  echo -e "${BLUE}Detecting your public IP address...${RESET}"
  local AUTO_IP=$(detect_public_ip)
  
  if [ -n "$AUTO_IP" ]; then
    echo -e "${GREEN}✓ Detected your public IP: $AUTO_IP${RESET}"
    read -rp "Local PUBLIC IP [$AUTO_IP]: " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-$AUTO_IP}
  else
    echo -e "${RED}✗ Could not detect public IP automatically${RESET}"
    echo -e "${YELLOW}Please enter your public IP address manually:${RESET}"
    read -rp "Local PUBLIC IP: " LOCAL_IP
    while [[ ! "$LOCAL_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
      echo -e "${RED}Invalid IP address format. Please enter a valid IP:${RESET}"
      read -rp "Local PUBLIC IP: " LOCAL_IP
    done
  fi
  
  # تشخیص کشور
  local LOCAL_COUNTRY=$(detect_country "$LOCAL_IP")
  echo -e "${BLUE}Detected country: ${GREEN}$LOCAL_COUNTRY${RESET}"
  echo

  # دریافت IP سرور مقابل
  read -rp "Remote PUBLIC IP: " REMOTE_IP
  while [[ ! "$REMOTE_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
    echo -e "${RED}Invalid IP address format. Please enter a valid IP:${RESET}"
    read -rp "Remote PUBLIC IP: " REMOTE_IP
  done
  
  # تشخیص کشور سرور مقابل
  local REMOTE_COUNTRY=$(detect_country "$REMOTE_IP")
  echo -e "${BLUE}Remote server country: ${GREEN}$REMOTE_COUNTRY${RESET}"
  echo

  # پیشنهاد IP بر اساس کشور و نوع تونل
  local SUGGESTED_LOCAL_IP=$(suggest_ip_for_country "$LOCAL_COUNTRY" "local" "$TUNNEL_TYPE")
  local SUGGESTED_REMOTE_IP=$(suggest_ip_for_country "$LOCAL_COUNTRY" "remote" "$TUNNEL_TYPE")
  
  echo -e "${MAGENTA}Suggested IP configuration:${RESET}"
  if [ "$LOCAL_COUNTRY" = "IR" ] || [ "$LOCAL_COUNTRY" = "Iran" ]; then
    echo -e "  Your tunnel IP (Iran server): ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    echo -e "  Remote tunnel IP: ${CYAN}$SUGGESTED_REMOTE_IP${RESET}"
  else
    echo -e "  Your tunnel IP (Foreign server): ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    echo -e "  Remote tunnel IP (Iran server): ${CYAN}$SUGGESTED_REMOTE_IP${RESET}"
  fi
  
  # برای SIT توضیح اضافی
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    echo -e "  ${YELLOW}Note: For SIT tunnels, IPv6 addresses will be configured separately${RESET}"
  fi
  
  read -rp "Your tunnel IP [$SUGGESTED_LOCAL_IP]: " TUN_IP
  TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
  
  # اعتبارسنجی فرمت IP
  while [[ ! "$TUN_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; do
    echo -e "${RED}Invalid format. Use format like 192.168.100.1/30:${RESET}"
    read -rp "Your tunnel IP [$SUGGESTED_LOCAL_IP]: " TUN_IP
    TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
  done
  
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
  
  # اعتبارسنجی IP پینگ
  while [[ ! "$PING_TARGET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
    echo -e "${RED}Invalid IP address format. Please enter a valid IP:${RESET}"
    read -rp "Remote PRIVATE IP for ping [$SUGGESTED_PING]: " PING_TARGET
    PING_TARGET=${PING_TARGET:-$SUGGESTED_PING}
  done
  
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
  
  echo -e "${BLUE}Configuration Summary:${RESET}"
  echo -e "  Tunnel name: ${GREEN}$DEV${RESET}"
  echo -e "  Tunnel type: ${CYAN}$TUNNEL_TYPE${RESET}"
  echo -e "  Local public IP: ${YELLOW}$LOCAL_IP${RESET}"
  echo -e "  Remote public IP: ${YELLOW}$REMOTE_IP${RESET}"
  echo -e "  Your tunnel IP: ${GREEN}$TUN_IP${RESET}"
  echo -e "  Ping target: ${CYAN}$PING_TARGET${RESET}"
  
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    echo -e "\n${MAGENTA}Additional SIT Tunnel Information:${RESET}"
    echo -e "  SIT (Simple Internet Transition) tunnels carry IPv6 traffic over IPv4"
    echo -e "  After tunnel is up, you can assign IPv6 addresses to the interface"
    echo -e "  Example IPv6 address: 2001:db8::1/64"
    echo -e "  Enable IPv6: echo 1 > /proc/sys/net/ipv6/conf/$DEV/accept_ra"
  fi
  
  echo -e "\n${YELLOW}Management commands:${RESET}"
  echo -e "  Check status: ${GREEN}systemctl status gre@$DEV${RESET}"
  echo -e "  Stop tunnel: ${RED}systemctl stop gre@$DEV gre-watch@$DEV${RESET}"
  echo -e "  View logs: ${BLUE}journalctl -u gre@$DEV${RESET}"
  echo -e "  View interface: ${CYAN}ip addr show $DEV${RESET}"
  
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  pause
}

# ... باقی توابع (list_all_tunnels, delete_tunnel, status_tunnels, show_help) همانند قبل باقی می‌مانند
# فقط show_help را به روز می‌کنم:

show_help() {
  show_banner
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}                      HELP & GUIDE                          ${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}\n"
  
  echo -e "${BLUE}📖 What is GRE/SIT Tunnel?${RESET}"
  echo "GRE (Generic Routing Encapsulation): IPv4 over IPv4 tunneling"
  echo "SIT (Simple Internet Transition): IPv6 over IPv4 tunneling"
  echo
  
  echo -e "${GREEN}🚀 Features:${RESET}"
  echo "• Automatic IP detection from multiple services"
  echo "• Country detection for smart IP assignment"
  echo "• Support for both GRE and SIT tunnels"
  echo "• Iran server: Gets .1 address (e.g., 192.168.100.1)"
  echo "• Foreign server: Gets .2 address (e.g., 192.168.100.2)"
  echo "• Automatic ping target suggestion"
  echo
  
  echo -e "${MAGENTA}🎯 IP Assignment Rules:${RESET}"
  echo "• GRE Tunnel: Uses 192.168.100.x - 192.168.200.x range"
  echo "• SIT Tunnel: Uses 192.168.150.x range (different from GRE)"
  echo "• Iran Server: Always gets .1 address"
  echo "• Foreign Server: Always gets .2 address"
  echo "• /30 subnet recommended (2 usable IPs)"
  echo
  
  echo -e "${YELLOW}📋 SIT Tunnel Specifics:${RESET}"
  echo "• SIT tunnels encapsulate IPv6 traffic over IPv4"
  echo "• IPv4 addresses are used for tunnel endpoints"
  echo "• IPv6 addresses can be assigned separately"
  echo "• Requires IPv6 support in kernel"
  echo
  
  echo -e "${CYAN}📋 Manual Management Commands:${RESET}"
  echo -e "  ${GREEN}List all tunnels:${RESET} ip link show | grep -E '(gre|sit)'"
  echo -e "  ${GREEN}Check status:${RESET} systemctl status gre@tunnel_name"
  echo -e "  ${GREEN}Start tunnel:${RESET} systemctl start gre@tunnel_name"
  echo -e "  ${GREEN}Stop tunnel:${RESET} systemctl stop gre@tunnel_name gre-watch@tunnel_name"
  echo -e "  ${GREEN}View logs:${RESET} journalctl -u gre@tunnel_name -f"
  echo -e "  ${GREEN}View config:${RESET} cat /etc/gre/tunnel_name.conf"
  echo
  
  echo -e "${BLUE}💡 Tips:${RESET}"
  echo "• Port 47 (GRE) must be open in firewall"
  echo "• SIT tunnels require IPv6 kernel modules"
  echo "• Use /30 subnet for point-to-point tunnels"
  echo "• Test connectivity with ping before using"
  echo -e "${MAGENTA}Created by: Parsa${RESET}"
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
