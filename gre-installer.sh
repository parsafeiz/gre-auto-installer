#!/bin/bash

CONFIG_DIR="/etc/gre"
SCRIPT="/usr/local/bin/gre.sh"
SERVICE_DIR="/etc/systemd/system"
LOG_FILE="/var/log/gre-tunnel.log"
WATCH_LOG="/var/log/gre-watch.log"

GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
WHITE="\e[97m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

# Create directories and log file
mkdir -p "$CONFIG_DIR"
touch "$LOG_FILE"
touch "$WATCH_LOG"

# ---------- Display Banner ----------

show_banner() {
  clear
  echo -e "${WHITE}"
  echo "=========================================================="
  echo "   _____ _____ ______     _______ _   _ _     _ _       "
  echo "  / ____|  __ \|  ____|   |__   __| \ | | |   (_) |      "
  echo " | |  __| |__) | |__ ______ | |  |  \| | |    _| | ___  "
  echo " | | |_ |  _  /|  __|______| |  | . \` | |   | | |/ _ \ "
  echo " | |__| | | \ \| |____     | |  | |\  | |___| | |  __/  "
  echo "  \_____|_|  \_\______|    |_|  |_| \_|_____|_|_|\___|  "
  echo "                                                        "
  echo "           GRE/SIT Tunnel Manager v3.1                 "
  echo "           Auto-Recovery Tunnel System                "
  echo "           Created by: Parsa                           "
  echo "=========================================================="
  echo -e "${RESET}"
}

# ---------- Helper Functions ----------

log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

watch_log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$WATCH_LOG"
}

pause() {
  echo
  read -rp "Press Enter to continue..."
}

# Configure firewall rules
configure_firewall() {
  local tunnel_type="$1"
  
  echo -e "${YELLOW}Configuring firewall rules...${RESET}"
  
  # Save current iptables rules
  iptables-save > /etc/iptables.rules.bak 2>/dev/null
  ip6tables-save > /etc/ip6tables.rules.bak 2>/dev/null
  
  # Add GRE protocol rules
  if ! iptables -C INPUT -p gre -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -p gre -j ACCEPT
    echo -e "${GREEN}✓ Added iptables rule: ACCEPT GRE protocol${RESET}"
  fi
  
  # Add SIT/IPv6 rules if needed
  if [ "$tunnel_type" = "sit" ] || ls "$CONFIG_DIR"/*.conf 2>/dev/null | grep -q "sit"; then
    if ! ip6tables -C INPUT -p ipv6 -j ACCEPT 2>/dev/null; then
      ip6tables -A INPUT -p ipv6 -j ACCEPT
      echo -e "${GREEN}✓ Added ip6tables rule: ACCEPT IPv6${RESET}"
    fi
  fi
  
  # Allow ICMP for ping
  if ! iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -p icmp -j ACCEPT
    echo -e "${GREEN}✓ Added iptables rule: ACCEPT ICMP${RESET}"
  fi
  
  # Save rules
  iptables-save > /etc/iptables/rules.v4 2>/dev/null
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
  
  log_message "Firewall configured for $tunnel_type tunnel"
}

# Validate IPv4 address
validate_ipv4() {
  local ip="$1"
  
  # Check general format
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    return 1
  fi
  
  # Check octets
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    # Check if numeric
    if [[ ! "$octet" =~ ^[0-9]+$ ]]; then
      return 1
    fi
    # Check range 0-255
    if [[ $octet -lt 0 || $octet -gt 255 ]]; then
      return 1
    fi
  done
  
  # Check special IPs
  if [[ "$ip" == "0.0.0.0" ]] || [[ "$ip" == "255.255.255.255" ]]; then
    return 1
  fi
  
  return 0
}

# Validate IPv6 address (simplified)
validate_ipv6() {
  local ip="$1"
  
  # Check general IPv6 format
  if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || [[ "$ip" =~ ^[0-9a-fA-F:]+/[0-9]+$ ]]; then
    return 0
  fi
  
  return 1
}

# Check if kernel modules are loaded
check_kernel_modules() {
  local tunnel_type="$1"
  
  if [ "$tunnel_type" = "sit" ]; then
    if ! lsmod | grep -q "sit" && ! lsmod | grep -q "ip_tunnel"; then
      echo -e "${YELLOW}Loading SIT kernel modules...${RESET}"
      modprobe ip_tunnel 2>/dev/null
      modprobe sit 2>/dev/null
      echo -e "${GREEN}✓ SIT kernel modules loaded${RESET}"
    fi
  else
    if ! lsmod | grep -q "ip_gre"; then
      echo -e "${YELLOW}Loading GRE kernel modules...${RESET}"
      modprobe ip_gre 2>/dev/null
      echo -e "${GREEN}✓ GRE kernel modules loaded${RESET}"
    fi
  fi
}

# Enable IP forwarding
enable_ip_forwarding() {
  # Enable IPv4 forwarding
  if [ "$(sysctl -n net.ipv4.ip_forward)" -eq 0 ]; then
    echo -e "${YELLOW}Enabling IPv4 forwarding...${RESET}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-gre-forwarding.conf
    echo -e "${GREEN}✓ IPv4 forwarding enabled${RESET}"
  fi
  
  # Enable IPv6 forwarding if SIT tunnels exist
  if ls "$CONFIG_DIR"/*.conf 2>/dev/null | grep -q "sit" || [ "$1" = "sit" ]; then
    if [ "$(sysctl -n net.ipv6.conf.all.forwarding)" -eq 0 ]; then
      echo -e "${YELLOW}Enabling IPv6 forwarding...${RESET}"
      sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
      echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-gre-forwarding.conf
      echo -e "${GREEN}✓ IPv6 forwarding enabled${RESET}"
    fi
  fi
  
  sysctl -p /etc/sysctl.d/99-gre-forwarding.conf 2>/dev/null
}

# Find next available tunnel name
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

# Detect server IP from interfaces
detect_server_ip() {
  local ip=""
  
  # First: Check IP from route to 8.8.8.8
  ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
  
  if validate_ipv4 "$ip"; then
    echo "$ip"
    return 0
  fi
  
  # Second: Check first non-loopback interface
  ip=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
  
  if validate_ipv4 "$ip"; then
    echo "$ip"
    return 0
  fi
  
  # Third: Check eth0
  ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
  
  if validate_ipv4 "$ip"; then
    echo "$ip"
    return 0
  fi
  
  # Fourth: Check ens3, enp0s3, etc
  for iface in $(ip link show 2>/dev/null | grep -oE '^[0-9]+: [a-z0-9]+:' | awk '{print $2}' | tr -d ':' | grep -E '^(eth|enp|ens|eno)' | head -1); do
    ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if validate_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  done
  
  echo ""
}

# Detect country based on IP (simplified)
detect_country() {
  local ip="$1"
  
  # If private IP
  if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$ip" =~ ^192\.168\. ]]; then
    echo "PRIVATE"
    return 0
  fi
  
  # Simple detection: If IP starts with 5 or in Iranian ranges
  if [[ "$ip" =~ ^5\. ]] || [[ "$ip" =~ ^(185\.|188\.|94\.|78\.|37\.27\.|46\.100\.|46\.209\.) ]]; then
    echo "IR"
  else
    echo "FOREIGN"
  fi
}

# Suggest IPv4 for GRE tunnel
suggest_gre_ip() {
  local country="$1"
  local tunnel_type="$2"  # local or remote
  
  # Find free subnet for GRE
  for i in {100..200}; do
    local config_exists=false
    # Check config files
    if ls "$CONFIG_DIR"/*.conf 1>/dev/null 2>&1; then
      for conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$conf" ] && grep -q "192\.168\.$i\." "$conf" && config_exists=true
      done
    fi
    
    if [ "$config_exists" = false ]; then
      if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
        if [ "$tunnel_type" = "local" ]; then
          echo "192.168.$i.1"  # IP only, no /30
        else
          echo "192.168.$i.2"
        fi
      else
        if [ "$tunnel_type" = "local" ]; then
          echo "192.168.$i.2"
        else
          echo "192.168.$i.1"
        fi
      fi
      return 0
    fi
  done
  
  # If all are used
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    echo "192.168.100.1"
  else
    echo "192.168.100.2"
  fi
}

# Suggest IPv6 for SIT tunnel
suggest_sit_ipv6() {
  local country="$1"
  local tunnel_type="$2"  # local or remote
  
  # Find free subnet for SIT (IPv6)
  for i in {1..100}; do
    local hex_i=$(printf "%02x" $i)
    local config_exists=false
    
    # Check config files
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
  
  # If all are used
  if [ "$country" = "IR" ] || [ "$country" = "Iran" ]; then
    echo "fd00:100::1/64"
  else
    echo "fd00:100::2/64"
  fi
}

# ---------- Tunnel Management Functions ----------

list_all_tunnels() {
  echo -e "\n${WHITE}=== Active Tunnel Interfaces ===${RESET}"
  echo -e "=========================================================="
  
  local found=0
  
  # GRE tunnels
  for iface in $(ip link show 2>/dev/null | grep -oE 'gre[0-9]+:' | tr -d ':' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IP")
    
    if echo "$status" | grep -q "UP"; then
      echo -e "${GREEN}[+] GRE  $iface${RESET}  $status  IP: ${WHITE}$ip${RESET}"
    else
      echo -e "${RED}[-] GRE  $iface${RESET}  $status  IP: ${WHITE}$ip${RESET}"
    fi
  done
  
  # SIT tunnels
  for iface in $(ip link show 2>/dev/null | grep -oE 'sit[0-9]+:' | tr -d ':' | sort -V); do
    found=1
    local status=$(ip link show "$iface" 2>/dev/null | grep -oE 'state (UP|DOWN)' || echo "state UNKNOWN")
    local ip=$(ip -6 addr show "$iface" 2>/dev/null | grep -oE 'inet6 [a-f0-9:]+/[0-9]+' | head -1 | cut -d' ' -f2 || echo "No IPv6")
    
    if echo "$status" | grep -q "UP"; then
      echo -e "${CYAN}[+] SIT  $iface${RESET}  $status  IPv6: ${WHITE}$ip${RESET}"
    else
      echo -e "${RED}[-] SIT  $iface${RESET}  $status  IPv6: ${WHITE}$ip${RESET}"
    fi
  done
  
  # Show configured but inactive tunnels
  local conf_files
  conf_files=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null) || true
  
  if [ -n "$conf_files" ]; then
    for conf in $conf_files; do
      local dev=$(basename "$conf" .conf)
      
      # If interface is not active
      if ! ip link show "$dev" &>/dev/null; then
        found=1
        local tunnel_type="gre"
        local ip=""
        local local_ip=""
        local remote_ip=""
        
        # Read info from config
        while IFS='=' read -r key value; do
          case "$key" in
            TUNNEL_TYPE) tunnel_type="$value" ;;
            TUN_IP) ip="$value" ;;
            LOCAL_IP) local_ip="$value" ;;
            REMOTE_IP) remote_ip="$value" ;;
          esac
        done < "$conf"
        
        if [ "$tunnel_type" = "sit" ]; then
          echo -e "${YELLOW}[.] SIT  $dev${RESET}  state DOWN  IPv6: ${WHITE}${ip:-"Unknown"}${RESET}  Remote: ${WHITE}${remote_ip:-"Unknown"}${RESET}"
        else
          echo -e "${YELLOW}[.] GRE  $dev${RESET}  state DOWN  IP: ${WHITE}${ip:-"Unknown"}${RESET}  Remote: ${WHITE}${remote_ip:-"Unknown"}${RESET}"
        fi
      fi
    done
  fi
  
  if [ $found -eq 0 ]; then
    echo -e "${YELLOW}No tunnel interfaces found${RESET}"
  fi
  
  echo -e "=========================================================="
}

# Function to start/stop tunnel manually
manage_tunnel() {
  local action="$1"  # start or stop
  local DEV="$2"
  
  if [ ! -f "$CONFIG_DIR/$DEV.conf" ]; then
    echo -e "${RED}Configuration file for $DEV not found!${RESET}"
    return 1
  fi
  
  # Read tunnel type
  local TUNNEL_TYPE="gre"
  if [ -f "$CONFIG_DIR/$DEV.conf" ]; then
    TUNNEL_TYPE=$(grep '^TUNNEL_TYPE=' "$CONFIG_DIR/$DEV.conf" | cut -d'=' -f2)
  fi
  
  echo -e "${YELLOW}${action^}ing $TUNNEL_TYPE tunnel $DEV...${RESET}"
  
  # Load kernel modules
  check_kernel_modules "$TUNNEL_TYPE"
  
  # Enable IP forwarding
  enable_ip_forwarding "$TUNNEL_TYPE"
  
  # Configure firewall
  configure_firewall "$TUNNEL_TYPE"
  
  # Execute script
  if [ -f "$SCRIPT" ]; then
    "$SCRIPT" "$action" "$DEV"
    
    if [ "$action" = "start" ]; then
      # Start services with retry logic
      for i in {1..3}; do
        systemctl start "gre@$DEV" 2>/dev/null
        sleep 2
        
        if ip link show "$DEV" &>/dev/null; then
          echo -e "${GREEN}✓ Tunnel $DEV started successfully${RESET}"
          
          # Start watchdog service
          systemctl start "gre-watch@$DEV" 2>/dev/null
          systemctl enable "gre-watch@$DEV" 2>/dev/null
          
          # Test connectivity
          echo -e "${WHITE}Testing tunnel connectivity...${RESET}"
          sleep 3
          "$SCRIPT" "status" "$DEV"
          break
        else
          echo -e "${YELLOW}Attempt $i: Tunnel not up, retrying...${RESET}"
          if [ $i -eq 3 ]; then
            echo -e "${RED}Failed to start tunnel $DEV after 3 attempts${RESET}"
            return 1
          fi
          sleep 2
        fi
      done
    else
      # Stop services
      systemctl stop "gre-watch@$DEV" 2>/dev/null
      systemctl disable "gre-watch@$DEV" 2>/dev/null
      systemctl stop "gre@$DEV" 2>/dev/null
      echo -e "${YELLOW}✓ Tunnel $DEV stopped${RESET}"
      echo -e "${YELLOW}Note: Tunnel will NOT auto-restart when manually stopped${RESET}"
    fi
  else
    echo -e "${RED}Runtime script not found!${RESET}"
    return 1
  fi
  
  return 0
}

# Function to restart tunnel
restart_tunnel() {
  local DEV="$1"
  
  echo -e "${YELLOW}Restarting tunnel $DEV...${RESET}"
  manage_tunnel "stop" "$DEV"
  sleep 3
  manage_tunnel "start" "$DEV"
  echo -e "${GREEN}✓ Tunnel $DEV restarted${RESET}"
}

delete_tunnel() {
  show_banner
  echo -e "=========================================================="
  echo -e "${WHITE}                     DELETE TUNNEL                    ${RESET}"
  echo -e "=========================================================="
  
  # List existing tunnels
  list_all_tunnels
  
  echo -e "\n${WHITE}=== Configured Tunnels ===${RESET}"
  
  # List config files
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
  
  echo -e "\n${WHITE}Select tunnel to delete:${RESET}"
  echo -e "=========================================================="
  
  local i=1
  for conf in "${CONFS[@]}"; do
    local dev=$(basename "$conf" .conf)
    local tunnel_type="gre"
    local local_ip=""
    local remote_ip=""
    
    # Read info from config
    while IFS='=' read -r key value; do
      case "$key" in
        TUNNEL_TYPE) tunnel_type="$value" ;;
        LOCAL_IP) local_ip="$value" ;;
        REMOTE_IP) remote_ip="$value" ;;
      esac
    done < "$conf"
    
    if ip link show "$dev" &>/dev/null; then
      echo -e "${GREEN}$i) $tunnel_type $dev${RESET} - ${WHITE}${local_ip} -> ${remote_ip}${RESET} (ACTIVE)"
    else
      echo -e "${YELLOW}$i) $tunnel_type $dev${RESET} - ${WHITE}${local_ip} -> ${remote_ip}${RESET} (INACTIVE)"
    fi
    ((i++))
  done
  
  echo -e "$i) Cancel"
  echo -e "=========================================================="
  
  read -rp "Select tunnel number [1-$i]: " selection
  
  # Validate selection
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt $i ]; then
    echo -e "${RED}Invalid selection!${RESET}"
    pause
    return 1
  fi
  
  # If Cancel selected
  if [ "$selection" -eq $i ]; then
    echo -e "${YELLOW}Operation cancelled.${RESET}"
    pause
    return 0
  fi
  
  local conf="${CONFS[$((selection-1))]}"
  local DEV=$(basename "$conf" .conf)
  
  # Read tunnel info
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
  
  echo -e "\n${RED}WARNING: You are about to delete $TUNNEL_TYPE tunnel $DEV${RESET}"
  echo -e "${RED}Local IP: $LOCAL_IP"
  echo -e "${RED}Remote IP: $REMOTE_IP${RESET}"
  echo -e "${RED}This action cannot be undone!${RESET}\n"
  
  read -rp "Type 'DELETE' to confirm: " confirm
  if [ "$confirm" != "DELETE" ]; then
    echo -e "${YELLOW}Deletion cancelled.${RESET}"
    pause
    return 0
  fi
  
  echo -e "\n${YELLOW}Deleting $TUNNEL_TYPE tunnel $DEV...${RESET}"
  
  # Stop services
  echo -e "${WHITE}Stopping services...${RESET}"
  systemctl stop "gre-watch@$DEV" 2>/dev/null
  systemctl stop "gre@$DEV" 2>/dev/null
  systemctl disable "gre-watch@$DEV" "gre@$DEV" 2>/dev/null
  
  # Remove tunnel
  echo -e "${WHITE}Removing tunnel interface...${RESET}"
  ip link set "$DEV" down 2>/dev/null
  ip tunnel del "$DEV" 2>/dev/null
  
  # Remove files
  echo -e "${WHITE}Removing configuration files...${RESET}"
  rm -f "$conf"
  rm -f "$SERVICE_DIR/gre@$DEV.service"
  rm -f "$SERVICE_DIR/gre-watch@$DEV.service"
  
  echo -e "${WHITE}Reloading systemd daemon...${RESET}"
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null
  
  log_message "$TUNNEL_TYPE tunnel $DEV deleted"
  
  echo -e "=========================================================="
  echo -e "${GREEN}✓ $TUNNEL_TYPE tunnel $DEV removed successfully!${RESET}"
  echo -e "=========================================================="
  pause
}

status_tunnels() {
  show_banner
  echo -e "=========================================================="
  echo -e "${WHITE}                   TUNNEL STATUS                    ${RESET}"
  echo -e "=========================================================="
  
  list_all_tunnels
  
  echo -e "\n${WHITE}=== Detailed Status ===${RESET}"
  echo -e "=========================================================="
  
  local found=0
  local total_up=0
  local total_down=0
  
  # List config files
  local conf_files
  conf_files=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null) || true
  
  if [ -n "$conf_files" ]; then
    for c in $conf_files; do
      found=1
      
      # Read config
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
      
      # Set color and symbol
      local type_color=$WHITE
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        type_color=$CYAN
      fi
      
      # Check status
      if ip link show "$DEV" &>/dev/null; then
        if [ "$TUNNEL_TYPE" = "sit" ]; then
          # For SIT use ping6
          if ping6 -c2 -W5 "$PING_TARGET" >/dev/null 2>&1; then
            echo -e "${GREEN}[+] ${type_color}$TUNNEL_TYPE${RESET} ${GREEN}$DEV${RESET}"
            echo -e "   Status: ${GREEN}UP${RESET}"
            echo -e "   Tunnel IPv6: ${WHITE}$TUN_IP${RESET}"
            echo -e "   Local IPv4: ${WHITE}$LOCAL_IP${RESET}"
            echo -e "   Remote IPv4: ${WHITE}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${GREEN}Success ✓${RESET}"
            ((total_up++))
          else
            echo -e "${YELLOW}[!] ${type_color}$TUNNEL_TYPE${RESET} ${YELLOW}$DEV${RESET}"
            echo -e "   Status: ${YELLOW}UP (ping failed)${RESET}"
            echo -e "   Tunnel IPv6: ${WHITE}$TUN_IP${RESET}"
            echo -e "   Local IPv4: ${WHITE}$LOCAL_IP${RESET}"
            echo -e "   Remote IPv4: ${WHITE}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${RED}Failed ✗${RESET}"
            ((total_down++))
          fi
        else
          # For GRE use regular ping
          if ping -c2 -W5 "$PING_TARGET" >/dev/null 2>&1; then
            echo -e "${GREEN}[+] ${type_color}$TUNNEL_TYPE${RESET} ${GREEN}$DEV${RESET}"
            echo -e "   Status: ${GREEN}UP${RESET}"
            echo -e "   Tunnel IP: ${WHITE}$TUN_IP${RESET}"
            echo -e "   Local IP: ${WHITE}$LOCAL_IP${RESET}"
            echo -e "   Remote IP: ${WHITE}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${GREEN}Success ✓${RESET}"
            ((total_up++))
          else
            echo -e "${YELLOW}[!] ${type_color}$TUNNEL_TYPE${RESET} ${YELLOW}$DEV${RESET}"
            echo -e "   Status: ${YELLOW}UP (ping failed)${RESET}"
            echo -e "   Tunnel IP: ${WHITE}$TUN_IP${RESET}"
            echo -e "   Local IP: ${WHITE}$LOCAL_IP${RESET}"
            echo -e "   Remote IP: ${WHITE}$REMOTE_IP${RESET}"
            echo -e "   Ping: ${RED}Failed ✗${RESET}"
            ((total_down++))
          fi
        fi
      else
        echo -e "${RED}[-] ${type_color}$TUNNEL_TYPE${RESET} ${RED}$DEV${RESET}"
        echo -e "   Status: ${RED}DOWN${RESET}"
        echo -e "   Tunnel IP: ${WHITE}$TUN_IP${RESET}"
        echo -e "   Local IP: ${WHITE}$LOCAL_IP${RESET}"
        echo -e "   Remote IP: ${WHITE}$REMOTE_IP${RESET}"
        ((total_down++))
      fi
      echo
    done
  fi
  
  [ "$found" -eq 0 ] && echo -e "${YELLOW}No tunnel configurations found${RESET}"
  
  echo -e "=========================================================="
  echo -e "${WHITE}Summary:${RESET}"
  echo -e "  Up tunnels: ${GREEN}$total_up${RESET}"
  echo -e "  Down tunnels: ${RED}$total_down${RESET}"
  echo -e "  Total: $((total_up + total_down))"
  
  if [ $total_up -gt 0 ]; then
    echo -e "\n${GREEN}Tunnels are running in background with auto-recovery.${RESET}"
    echo -e "${WHITE}Watchdog services will automatically restart failed tunnels.${RESET}"
  fi
  
  echo -e "=========================================================="
  pause
}

# Tunnel management menu
manage_tunnel_menu() {
  show_banner
  echo -e "=========================================================="
  echo -e "${WHITE}                TUNNEL MANAGEMENT                  ${RESET}"
  echo -e "=========================================================="
  
  # List config files
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
  
  echo -e "\n${WHITE}Select tunnel to manage:${RESET}"
  echo -e "=========================================================="
  
  local i=1
  for conf in "${CONFS[@]}"; do
    local dev=$(basename "$conf" .conf)
    local tunnel_type="gre"
    local local_ip=""
    local remote_ip=""
    
    # Read info from config
    while IFS='=' read -r key value; do
      case "$key" in
        TUNNEL_TYPE) tunnel_type="$value" ;;
        LOCAL_IP) local_ip="$value" ;;
        REMOTE_IP) remote_ip="$value" ;;
      esac
    done < "$conf"
    
    if ip link show "$dev" &>/dev/null; then
      echo -e "${GREEN}$i) $tunnel_type $dev${RESET} - ${WHITE}${local_ip} -> ${remote_ip}${RESET} (UP)"
    else
      echo -e "${RED}$i) $tunnel_type $dev${RESET} - ${WHITE}${local_ip} -> ${remote_ip}${RESET} (DOWN)"
    fi
    ((i++))
  done
  
  echo -e "$i) Back to main menu"
  echo -e "=========================================================="
  
  read -rp "Select tunnel number [1-$i]: " selection
  
  # Validate selection
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt $i ]; then
    echo -e "${RED}Invalid selection!${RESET}"
    pause
    return 1
  fi
  
  # If Back selected
  if [ "$selection" -eq $i ]; then
    return 0
  fi
  
  local conf="${CONFS[$((selection-1))]}"
  local DEV=$(basename "$conf" .conf)
  
  # Read tunnel type
  local TUNNEL_TYPE="gre"
  if [ -f "$conf" ]; then
    TUNNEL_TYPE=$(grep '^TUNNEL_TYPE=' "$conf" | cut -d'=' -f2)
  fi
  
  # Check current status
  local is_up=false
  if ip link show "$DEV" &>/dev/null; then
    is_up=true
  fi
  
  echo -e "\n${WHITE}Selected tunnel: $TUNNEL_TYPE $DEV${RESET}"
  echo -e "Current status: $([ "$is_up" = true ] && echo -e "${GREEN}UP${RESET}" || echo -e "${RED}DOWN${RESET}")"
  echo -e "\n${WHITE}Select action:${RESET}"
  echo "1) Start tunnel"
  echo "2) Stop tunnel"
  echo "3) Restart tunnel"
  echo "4) Check status"
  echo "5) View logs"
  echo "6) Back"
  
  read -rp "Enter choice [1-6]: " action_choice
  
  case "$action_choice" in
    1)
      manage_tunnel "start" "$DEV"
      ;;
    2)
      manage_tunnel "stop" "$DEV"
      ;;
    3)
      restart_tunnel "$DEV"
      ;;
    4)
      echo -e "\n${WHITE}Checking status of $DEV...${RESET}"
      if [ -f "$SCRIPT" ]; then
        "$SCRIPT" "status" "$DEV"
      else
        echo -e "${RED}Runtime script not found!${RESET}"
      fi
      ;;
    5)
      echo -e "\n${WHITE}Recent logs for $DEV:${RESET}"
      echo -e "=========================================================="
      grep "$DEV" "$LOG_FILE" | tail -10
      echo -e "\n${WHITE}Watchdog logs:${RESET}"
      echo -e "=========================================================="
      grep "$DEV" "$WATCH_LOG" | tail -10
      ;;
    6)
      return 0
      ;;
    *)
      echo -e "${RED}Invalid choice!${RESET}"
      ;;
  esac
  
  pause
  return 0
}

# ---------- GRE/SIT Runtime Script ----------

create_or_update_gre_script() {
  # Only create if script doesn't exist
  if [ ! -f "$SCRIPT" ]; then
    echo -e "${YELLOW}Creating GRE/SIT runtime script...${RESET}"
    
    cat > "$SCRIPT" <<'EOF'
#!/bin/bash

CONF="/etc/gre/$2.conf"
[ ! -f "$CONF" ] && {
  echo "Error: Config file not found: $CONF"
  exit 1
}

# Read variables from config
DEV=""; LOCAL_IP=""; REMOTE_IP=""; TUN_IP=""; PING_TARGET=""; TUNNEL_TYPE=""
while IFS='=' read -r key value; do
  [[ $key =~ ^[[:alpha:]_][[:alnum:]_]*$ ]] || continue
  value=${value#\"}; value=${value%\"}
  declare "$key=$value" 2>/dev/null
done < "$CONF"

# Load appropriate module
if [ "$TUNNEL_TYPE" = "sit" ]; then
  modprobe ip_tunnel 2>/dev/null
  modprobe sit 2>/dev/null
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Loaded SIT tunnel modules for $DEV" >> /var/log/gre-tunnel.log
else
  modprobe ip_gre 2>/dev/null
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Loaded GRE tunnel modules for $DEV" >> /var/log/gre-tunnel.log
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
if [ "$TUNNEL_TYPE" = "sit" ]; then
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
fi

# Configure firewall
if [ "$TUNNEL_TYPE" = "sit" ]; then
  ip6tables -A INPUT -p ipv6 -j ACCEPT 2>/dev/null
else
  iptables -A INPUT -p gre -j ACCEPT 2>/dev/null
fi
iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null

case "$1" in
  start)
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting $TUNNEL_TYPE tunnel $DEV" | tee -a /var/log/gre-tunnel.log
    
    # Remove existing tunnel if exists
    ip tunnel del "$DEV" 2>/dev/null
    sleep 1
    
    # Create tunnel based on type
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      ip tunnel add "$DEV" mode sit local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
      if [ $? -ne 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed to create SIT tunnel $DEV" >> /var/log/gre-tunnel.log
        exit 1
      fi
    else
      ip tunnel add "$DEV" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
      if [ $? -ne 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed to create GRE tunnel $DEV" >> /var/log/gre-tunnel.log
        exit 1
      fi
    fi
    
    # Set IP based on tunnel type
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      ip -6 addr add "$TUN_IP" dev "$DEV"
      # Enable IPv6
      sysctl -w net.ipv6.conf.$DEV.disable_ipv6=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.autoconf=0 >/dev/null 2>&1
      sysctl -w net.ipv6.conf.$DEV.accept_ra=0 >/dev/null 2>&1
    else
      # For GRE: if IP lacks subnet mask, add /30
      if [[ "$TUN_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        TUN_IP="$TUN_IP/30"
      fi
      ip addr add "$TUN_IP" dev "$DEV"
    fi
    
    ip link set "$DEV" up
    
    # Wait for interface to stabilize
    sleep 2
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $TUNNEL_TYPE tunnel $DEV started with IP $TUN_IP" >> /var/log/gre-tunnel.log
    echo "✓ $TUNNEL_TYPE tunnel $DEV started successfully"
    
    # Show interface details
    echo "Interface details:"
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      ip -6 addr show dev "$DEV" 2>/dev/null || echo "No IPv6 address configured"
    else
      ip addr show dev "$DEV" 2>/dev/null || echo "No IPv4 address configured"
    fi
    
    # Initial connectivity test (non-blocking)
    echo "Performing initial connectivity test..."
    if [ "$TUNNEL_TYPE" = "sit" ]; then
      timeout 10 ping6 -c2 "$PING_TARGET" >/dev/null 2>&1 && \
        echo "✓ Initial connectivity: PASS" || \
        echo "⚠ Initial connectivity: FAIL (may need more time)"
    else
      timeout 10 ping -c2 "$PING_TARGET" >/dev/null 2>&1 && \
        echo "✓ Initial connectivity: PASS" || \
        echo "⚠ Initial connectivity: FAIL (may need more time)"
    fi
    ;;
  stop)
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Stopping $TUNNEL_TYPE tunnel $DEV" | tee -a /var/log/gre-tunnel.log
    
    # Mark as manually stopped (prevent auto-restart)
    touch "/tmp/gre-$DEV-manually-stopped" 2>/dev/null
    
    ip link set "$DEV" down 2>/dev/null
    sleep 1
    ip tunnel del "$DEV" 2>/dev/null
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $TUNNEL_TYPE tunnel $DEV stopped" >> /var/log/gre-tunnel.log
    echo "✓ $TUNNEL_TYPE tunnel $DEV stopped"
    echo "Note: Tunnel will NOT auto-restart (manually stopped)"
    ;;
  restart)
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Restarting $TUNNEL_TYPE tunnel $DEV" >> /var/log/gre-tunnel.log
    echo "Restarting $TUNNEL_TYPE tunnel $DEV..."
    
    # Remove manual stop flag
    rm -f "/tmp/gre-$DEV-manually-stopped" 2>/dev/null
    
    "$0" stop "$DEV"
    sleep 3
    "$0" start "$DEV"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $TUNNEL_TYPE tunnel $DEV restarted" >> /var/log/gre-tunnel.log
    ;;
  check)
    # Skip check if manually stopped
    if [ -f "/tmp/gre-$DEV-manually-stopped" ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Manually stopped, skipping check" >> /var/log/gre-watch.log
      exit 0
    fi
    
    # Check if interface exists
    if ! ip link show "$DEV" &>/dev/null; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Interface not found, restarting..." >> /var/log/gre-watch.log
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Interface not found, restarting tunnel" >> /var/log/gre-tunnel.log
      "$0" restart "$DEV"
      exit 0
    fi
    
    # Enhanced ping check with multiple attempts
    local max_attempts=3
    local attempts=0
    local success=0
    
    for ((attempts=1; attempts<=max_attempts; attempts++)); do
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        if timeout 15 ping6 -c2 -W5 "$PING_TARGET" >/dev/null 2>&1; then
          success=1
          break
        fi
      else
        if timeout 15 ping -c2 -W5 "$PING_TARGET" >/dev/null 2>&1; then
          success=1
          break
        fi
      fi
      
      if [ $attempts -lt $max_attempts ]; then
        sleep 3
      fi
    done
    
    if [ $success -eq 0 ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Ping FAILED after $max_attempts attempts, restarting..." >> /var/log/gre-watch.log
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Connectivity lost, restarting tunnel" >> /var/log/gre-tunnel.log
      "$0" restart "$DEV"
    else
      # Log successful check periodically (every 10th check)
      local check_count=$((RANDOM % 10))
      if [ $check_count -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $DEV: Ping OK" >> /var/log/gre-watch.log
      fi
    fi
    ;;
  status)
    echo "=== Tunnel Status: $DEV ==="
    echo "Type: $TUNNEL_TYPE"
    echo "Local IP: $LOCAL_IP"
    echo "Remote IP: $REMOTE_IP"
    echo "Tunnel IP: $TUN_IP"
    echo "Ping Target: $PING_TARGET"
    
    if ip link show "$DEV" &>/dev/null; then
      echo -e "Interface: \e[32mUP\e[0m"
      echo "Interface details:"
      ip link show "$DEV" 2>/dev/null | grep -E "state|mtu" | head -1
      
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        echo "IPv6 address:"
        ip -6 addr show dev "$DEV" 2>/dev/null | grep inet6 || echo "  No IPv6 address"
      else
        echo "IPv4 address:"
        ip addr show dev "$DEV" 2>/dev/null | grep inet || echo "  No IPv4 address"
      fi
      
      # Test connectivity
      echo -n "Connectivity test: "
      if [ "$TUNNEL_TYPE" = "sit" ]; then
        if timeout 5 ping6 -c1 "$PING_TARGET" >/dev/null 2>&1; then
          echo -e "\e[32mPASS\e[0m"
        else
          echo -e "\e[31mFAIL\e[0m"
        fi
      else
        if timeout 5 ping -c1 "$PING_TARGET" >/dev/null 2>&1; then
          echo -e "\e[32mPASS\e[0m"
        else
          echo -e "\e[31mFAIL\e[0m"
        fi
      fi
    else
      echo -e "Interface: \e[31mDOWN\e[0m"
      echo "Note: Watchdog will auto-restart this tunnel"
    fi
    
    # Check if manually stopped
    if [ -f "/tmp/gre-$DEV-manually-stopped" ]; then
      echo -e "\e[33m⚠ Manually stopped - auto-recovery disabled\e[0m"
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
    echo -e "${WHITE}✓ GRE/SIT runtime script already exists${RESET}"
  fi
}

# ---------- Services ----------

create_service() {
  local DEV="$1"
  local TUNNEL_TYPE="$2"
  
  echo -e "\n${YELLOW}Creating systemd services for $DEV ($TUNNEL_TYPE)...${RESET}"
  
  # Main tunnel service
  cat > "$SERVICE_DIR/gre@$DEV.service" <<EOF
[Unit]
Description=$TUNNEL_TYPE Tunnel $DEV
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SCRIPT start $DEV
ExecStop=$SCRIPT stop $DEV
Restart=no
RestartSec=10

# Auto-recovery on failure
ExecStartPost=/bin/bash -c 'if ! systemctl is-active --quiet gre-watch@$DEV; then systemctl start gre-watch@$DEV; fi'

[Install]
WantedBy=multi-user.target
EOF

  # Watchdog service - aggressive auto-recovery
  cat > "$SERVICE_DIR/gre-watch@$DEV.service" <<EOF
[Unit]
Description=$TUNNEL_TYPE Watchdog $DEV
After=gre@$DEV.service
Requires=gre@$DEV.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do $SCRIPT check $DEV; sleep 30; done'
Restart=always
RestartSec=5
User=root

# Prevent watchdog from being stopped by systemd
IgnoreSIGPIPE=no
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
  
  echo -e "${GREEN}✓ Systemd services created for $DEV${RESET}"
}

# ---------- Create Tunnel ----------

create_tunnel() {
  show_banner
  echo -e "=========================================================="
  echo -e "${WHITE}                    CREATE NEW TUNNEL                ${RESET}"
  echo -e "=========================================================="
  
  # Pre-flight checks
  echo -e "${YELLOW}Performing system checks...${RESET}"
  check_kernel_modules "gre"
  enable_ip_forwarding
  configure_firewall "gre"
  
  # Select tunnel type
  echo -e "\n${WHITE}Select tunnel type:${RESET}"
  echo "1) GRE Tunnel - IPv4 over IPv4 (Recommended)"
  echo "2) SIT Tunnel - IPv6 over IPv4"
  read -rp "Enter choice [1-2, default=1]: " tunnel_choice
  
  case "$tunnel_choice" in
    2) TUNNEL_TYPE="sit" ;;
    *) TUNNEL_TYPE="gre" ;;
  esac
  
  local DEV=$(next_tunnel_name "$TUNNEL_TYPE")
  echo -e "\n${WHITE}Tunnel name: ${GREEN}$DEV${RESET}\n"

  # Detect server IP
  echo -e "${WHITE}Detecting server IP address...${RESET}"
  local SERVER_IP=$(detect_server_ip)
  
  if [ -n "$SERVER_IP" ]; then
    echo -e "${GREEN}✓ Detected server IP: $SERVER_IP${RESET}"
    while true; do
      read -rp "Local server IP [$SERVER_IP]: " LOCAL_IP
      LOCAL_IP=${LOCAL_IP:-$SERVER_IP}
      if validate_ipv4 "$LOCAL_IP"; then
        break
      else
        echo -e "${RED}Invalid IP address! Please enter a valid IPv4 address (format: x.x.x.x)${RESET}"
      fi
    done
  else
    echo -e "${RED}✗ Could not detect server IP${RESET}"
    while true; do
      read -rp "Local server IP: " LOCAL_IP
      if validate_ipv4 "$LOCAL_IP"; then
        break
      else
        echo -e "${RED}Invalid IP address! Please enter a valid IPv4 address (format: x.x.x.x)${RESET}"
      fi
    done
  fi
  
  echo

  # Get remote server IP
  while true; do
    read -rp "Remote server IP: " REMOTE_IP
    if validate_ipv4 "$REMOTE_IP"; then
      break
    else
      echo -e "${RED}Invalid IP address! Please enter a valid IPv4 address (format: x.x.x.x)${RESET}"
    fi
  done
  
  echo

  # Suggest IP based on tunnel type
  local LOCAL_COUNTRY=$(detect_country "$LOCAL_IP")
  
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    SUGGESTED_LOCAL_IP=$(suggest_sit_ipv6 "$LOCAL_COUNTRY" "local")
    echo -e "${WHITE}Suggested IPv6 address: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    
    while true; do
      read -rp "Your tunnel IPv6 [$SUGGESTED_LOCAL_IP]: " TUN_IP
      TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
      if validate_ipv6 "$TUN_IP"; then
        break
      else
        echo -e "${RED}Invalid IPv6 address! Please enter a valid IPv6 address${RESET}"
      fi
    done
    
    # Suggest ping IP
    local base_ip=$(echo "$TUN_IP" | sed 's/::[0-9a-f]*\/.*//')
    if [[ "$TUN_IP" =~ ::1/ ]]; then
      SUGGESTED_PING="${base_ip}::2"
    else
      SUGGESTED_PING="${base_ip}::1"
    fi
  else
    SUGGESTED_LOCAL_IP=$(suggest_gre_ip "$LOCAL_COUNTRY" "local")
    echo -e "${WHITE}Suggested IPv4 address: ${GREEN}$SUGGESTED_LOCAL_IP${RESET}"
    echo -e "${YELLOW}Note: Only IP address (without /30). /30 will be added automatically.${RESET}"
    
    while true; do
      read -rp "Your tunnel IPv4 [$SUGGESTED_LOCAL_IP]: " TUN_IP
      TUN_IP=${TUN_IP:-$SUGGESTED_LOCAL_IP}
      if validate_ipv4 "$TUN_IP"; then
        break
      else
        echo -e "${RED}Invalid IP address! Please enter a valid IPv4 address (format: x.x.x.x)${RESET}"
      fi
    done
    
    # Suggest ping IP
    local base_ip=$(echo "$TUN_IP" | sed 's/\.[0-9]*$//')
    local last_digit=$(echo "$TUN_IP" | awk -F. '{print $4}')
    if [ "$last_digit" = "1" ]; then
      SUGGESTED_PING="${base_ip}.2"
    else
      SUGGESTED_PING="${base_ip}.1"
    fi
  fi
  
  echo -e "${WHITE}Suggested ping target: ${GREEN}$SUGGESTED_PING${RESET}"
  
  if [ "$TUNNEL_TYPE" = "sit" ]; then
    while true; do
      read -rp "Ping target IPv6 [$SUGGESTED_PING]: " PING_TARGET
      PING_TARGET=${PING_TARGET:-$SUGGESTED_PING}
      if validate_ipv6 "$PING_TARGET"; then
        break
      else
        echo -e "${RED}Invalid IPv6 address! Please enter a valid IPv6 address${RESET}"
      fi
    done
  else
    while true; do
      read -rp "Ping target IPv4 [$SUGGESTED_PING]: " PING_TARGET
      PING_TARGET=${PING_TARGET:-$SUGGESTED_PING}
      if validate_ipv4 "$PING_TARGET"; then
        break
      else
        echo -e "${RED}Invalid IP address! Please enter a valid IPv4 address (format: x.x.x.x)${RESET}"
      fi
    done
  fi
  
  echo

  # Create config file (save IP without /30 for GRE)
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
LOCAL_COUNTRY=$LOCAL_COUNTRY
EOF

  echo -e "${GREEN}✓ Configuration saved to $CONFIG_DIR/$DEV.conf${RESET}"

  # Create or update runtime script
  create_or_update_gre_script
  
  # Create systemd service
  create_service "$DEV" "$TUNNEL_TYPE"

  echo -e "\n${YELLOW}Starting tunnel...${RESET}"
  systemctl daemon-reload
  
  # Enable and start services
  systemctl enable --now "gre@$DEV" >/dev/null 2>&1
  systemctl enable --now "gre-watch@$DEV" >/dev/null 2>&1
  
  # Remove any manual stop flag
  rm -f "/tmp/gre-$DEV-manually-stopped" 2>/dev/null
  
  # Manually start tunnel to ensure it's up
  sleep 2
  manage_tunnel "start" "$DEV"

  echo -e "=========================================================="
  echo -e "${GREEN}✓ $TUNNEL_TYPE tunnel $DEV created successfully!${RESET}"
  echo -e "=========================================================="
  
  # Show tunnel info
  echo -e "\n${WHITE}Tunnel Information:${RESET}"
  echo -e "  Name: ${WHITE}$DEV${RESET}"
  echo -e "  Type: ${WHITE}$TUNNEL_TYPE${RESET}"
  echo -e "  Local IP: ${WHITE}$LOCAL_IP${RESET}"
  echo -e "  Remote IP: ${WHITE}$REMOTE_IP${RESET}"
  
  if [ "$TUNNEL_TYPE" = "gre" ]; then
    echo -e "  Tunnel IP: ${WHITE}$TUN_IP/30${RESET}"
    echo -e "  Ping target: ${WHITE}$PING_TARGET${RESET}"
  else
    echo -e "  Tunnel IPv6: ${WHITE}$TUN_IP${RESET}"
    echo -e "  Ping target: ${WHITE}$PING_TARGET${RESET}"
  fi
  
  echo -e "\n${GREEN}Auto-recovery features enabled:${RESET}"
  echo -e "  • Tunnel will auto-restart if interface goes down"
  echo -e "  • Connectivity checked every 30 seconds"
  echo -e "  • Auto-recovery on ping failure (3 attempts)"
  echo -e "  • Firewall rules automatically configured"
  
  echo -e "\n${WHITE}Management commands:${RESET}"
  echo -e "  Check status: ${WHITE}systemctl status gre@$DEV${RESET}"
  echo -e "  View logs: ${WHITE}journalctl -u gre@$DEV${RESET}"
  echo -e "  Stop tunnel: ${WHITE}$SCRIPT stop $DEV${RESET}"
  echo -e "  Note: Manual stop disables auto-recovery until next start${RESET}"
  
  pause
}

# ---------- Main Menu ----------

while true; do
  show_banner
  echo -e "=========================================================="
  echo -e "${WHITE}                      MAIN MENU                     ${RESET}"
  echo -e "=========================================================="
  
  echo -e "${WHITE}  1) Create new tunnel${RESET}"
  echo -e "${WHITE}  2) Manage tunnels (Start/Stop/Restart)${RESET}"
  echo -e "${WHITE}  3) Delete tunnel${RESET}"
  echo -e "${WHITE}  4) Tunnel status${RESET}"
  echo -e "${WHITE}  5) List all tunnels${RESET}"
  echo -e "${WHITE}  6) View system logs${RESET}"
  echo -e "${WHITE}  7) Configure firewall${RESET}"
  echo -e "${WHITE}  8) Exit${RESET}"
  echo
  echo -e "=========================================================="
  read -rp "Select option [1-8]: " opt

  case "$opt" in
    1) create_tunnel ;;
    2) manage_tunnel_menu ;;
    3) delete_tunnel ;;
    4) status_tunnels ;;
    5) 
      show_banner
      list_all_tunnels
      pause
      ;;
    6)
      show_banner
      echo -e "=========================================================="
      echo -e "${WHITE}                    SYSTEM LOGS                    ${RESET}"
      echo -e "=========================================================="
      echo -e "\n${WHITE}Tunnel logs (last 20 lines):${RESET}"
      echo -e "------------------------------------------"
      tail -20 "$LOG_FILE" 2>/dev/null || echo "No log file found"
      echo -e "\n${WHITE}Watchdog logs (last 20 lines):${RESET}"
      echo -e "------------------------------------------"
      tail -20 "$WATCH_LOG" 2>/dev/null || echo "No watchdog log file found"
      pause
      ;;
    7)
      show_banner
      echo -e "=========================================================="
      echo -e "${WHITE}                 FIREWALL CONFIG                  ${RESET}"
      echo -e "=========================================================="
      configure_firewall "both"
      echo -e "\n${GREEN}Current firewall rules:${RESET}"
      echo -e "------------------------------------------"
      echo -e "${WHITE}IPv4 rules (GRE/ICMP):${RESET}"
      iptables -L INPUT -n | grep -E "(gre|icmp)" || echo "No GRE/ICMP rules found"
      echo -e "\n${WHITE}IPv6 rules (SIT):${RESET}"
      ip6tables -L INPUT -n | grep -E "(ipv6)" || echo "No IPv6 rules found"
      pause
      ;;
    8) 
      echo -e "\n${WHITE}Goodbye!${RESET}"
      exit 0
      ;;
    *) 
      echo -e "\n${RED}Invalid option!${RESET}"
      sleep 1
      ;;
  esac
done
