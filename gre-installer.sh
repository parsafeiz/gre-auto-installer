#!/bin/bash

echo "=============================="
echo " GRE Tunnel Auto Installer"
echo "=============================="
echo
read -p "Server location (iran/khareji): " LOCATION

read -p "Local PUBLIC IP: " LOCAL_IP
read -p "Remote PUBLIC IP: " REMOTE_IP

# defaults
DEV="gre1"
NETMASK="/30"

if [ "$LOCATION" == "iran" ]; then
  TUN_IP="192.168.100.1$NETMASK"
  PING_TARGET="192.168.100.2"
elif [ "$LOCATION" == "khareji" ]; then
  TUN_IP="192.168.100.2$NETMASK"
  PING_TARGET="192.168.100.1"
else
  echo "❌ only iran or khareji allowed"
  exit 1
fi

echo
echo "Tunnel IP      : $TUN_IP"
echo "Ping target    : $PING_TARGET"
echo "Local IP       : $LOCAL_IP"
echo "Remote IP      : $REMOTE_IP"
echo
sleep 2

echo "▶ Creating gre.sh ..."

cat > /usr/local/bin/gre.sh <<EOF
#!/bin/bash

LOCAL_IP="$LOCAL_IP"
REMOTE_IP="$REMOTE_IP"
TUN_IP="$TUN_IP"
DEV="$DEV"
PING_TARGET="$PING_TARGET"

case "\$1" in
  start)
    ip tunnel del \$DEV 2>/dev/null
    ip tunnel add \$DEV mode gre local \$LOCAL_IP remote \$REMOTE_IP ttl 255
    ip addr add \$TUN_IP dev \$DEV
    ip link set \$DEV up
    ;;
  stop)
    ip link set \$DEV down 2>/dev/null
    ip tunnel del \$DEV 2>/dev/null
    ;;
  restart)
    \$0 stop
    sleep 1
    \$0 start
    ;;
  check)
    ping -c 3 -W 2 \$PING_TARGET >/dev/null
    if [ \$? -ne 0 ]; then
      echo "\$(date) GRE down, restarting..." >> /var/log/gre-watch.log
      \$0 restart
    fi
    ;;
esac
EOF

chmod +x /usr/local/bin/gre.sh

echo "▶ Creating gre.service ..."

cat > /etc/systemd/system/gre.service <<EOF
[Unit]
Description=GRE Tunnel Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre.sh start
ExecStop=/usr/local/bin/gre.sh stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "▶ Creating gre-watch.service ..."

cat > /etc/systemd/system/gre-watch.service <<EOF
[Unit]
Description=GRE Ping Watchdog
After=gre.service

[Service]
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/gre.sh check; sleep 10; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "▶ Enabling services..."

systemctl daemon-reload
systemctl enable gre gre-watch
systemctl restart gre gre-watch

echo
echo "✅ GRE tunnel installed and monitored successfully"
echo "Logs: tail -f /var/log/gre-watch.log"
