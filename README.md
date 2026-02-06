


GRE Tunnel Auto Installer 🔗
یک اسکریپت کامل برای راه‌اندازی خودکار تونل GRE بین دو سرور لینوکس با قابلیت Watchdog و Systemd Service

https://img.shields.io/badge/License-MIT-blue.svg
https://img.shields.io/badge/Bash-Script-green.svg
https://img.shields.io/badge/Systemd-Service-red.svg

📌 فهرست مطالب
🚀 نصب خودکار (یک خطی)

🔧 نصب دستی کامل

⚙️ پیکربندی

🛠️ دستورات مدیریتی

🔍 عیب‌یابی

❓ سوالات متداول

📞 پشتیبانی

🚀 نصب خودکار (یک خطی)
تنها با یک دستور همه چیز نصب می‌شود:

bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)
✅ پس از اجرا:

تونل GRE ایجاد می‌شود

سرویس Systemd نصب می‌شود

Watchdog فعال می‌شود

لاگ‌گیری فعال می‌شود

🔧 نصب دستی کامل
اگر می‌خواهید کنترل کامل روی فرآیند داشته باشید، تمام دستورات زیر را به ترتیب اجرا کنید:

1️⃣ نصب پیش‌نیازها
bash
# برای Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y curl iproute2

# برای CentOS/RHEL
sudo yum install -y curl iproute
2️⃣ ایجاد اسکریپت اصلی GRE
bash
sudo tee /usr/local/bin/gre.sh > /dev/null << 'EOF'
#!/bin/bash

# 🔧 تنظیمات شما - این قسمت را تغییر دهید
LOCAL_IP="103.45.246.176"      # IP عمومی سرور فعلی شما
بابا همرو برام تو یک فایل بزار بزارم تو REAME
'گیت هاب این پروژه
GRE Tunnel Auto Installer 🔗
یک اسکریپت کامل برای راه‌اندازی خودکار تونل GRE بین دو سرور لینوکس

🚀 نصب خودکار (توصیه شده)
bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)
🔧 نصب دستی کامل
تمام دستورات زیر را به ترتیب کپی و اجرا کنید:

1. نصب پیش‌نیازها
bash
# برای Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y curl iproute2

# برای CentOS/RHEL
sudo yum install -y curl iproute
2. ایجاد اسکریپت اصلی
bash
sudo tee /usr/local/bin/gre.sh > /dev/null << 'EOF'
#!/bin/bash

# 🔧 تنظیمات شما - این قسمت را تغییر دهید
LOCAL_IP="103.45.246.176"      # IP عمومی سرور فعلی
REMOTE_IP="89.44.242.102"      # IP عمومی سرور مقابل
TUN_IP="10.10.10.2/30"         # IP تونل محلی (مثال: 10.10.10.2/30)
DEV="gre1"                     # نام اینترفیس تونل
PING_TARGET="10.10.10.1"       # IP تونل مقابل

case "$1" in
  start)
    echo "🚀 Starting GRE tunnel..."
    ip tunnel del $DEV 2>/dev/null
    ip tunnel add $DEV mode gre local $LOCAL_IP remote $REMOTE_IP ttl 255
    ip addr add $TUN_IP dev $DEV
    ip link set $DEV up
    echo "✅ GRE tunnel started successfully"
    ;;
  stop)
    echo "🛑 Stopping GRE tunnel..."
    ip link set $DEV down 2>/dev/null
    ip tunnel del $DEV 2>/dev/null
    echo "✅ GRE tunnel stopped"
    ;;
  restart)
    echo "🔄 Restarting GRE tunnel..."
    $0 stop
    sleep 2
    $0 start
    ;;
  check)
    ping -c 3 -W 2 $PING_TARGET >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') GRE tunnel is down, restarting..." >> /var/log/gre-watch.log
      $0 restart
    fi
    ;;
  status)
    echo "=== GRE Tunnel Status ==="
    ip tunnel show $DEV 2>/dev/null || echo "❌ Tunnel $DEV is not running"
    echo ""
    echo "=== Interface Status ==="
    ip addr show $DEV 2>/dev/null || echo "❌ Interface $DEV not found"
    echo ""
    echo "=== Routing Table ==="
    ip route | grep $DEV 2>/dev/null || echo "No routes found for $DEV"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|check|status}"
    exit 1
    ;;
esac
EOF
3. تنظیم مجوزهای اجرایی
bash
sudo chmod +x /usr/local/bin/gre.sh
4. ایجاد سرویس Systemd برای GRE
bash
sudo tee /etc/systemd/system/gre.service > /dev/null << 'EOF'
[Unit]
Description=GRE Tunnel Service
After=network.target
Wants=network.target
Requires=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre.sh start
ExecStop=/usr/local/bin/gre.sh stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
5. ایجاد سرویس Watchdog برای نظارت
bash
sudo tee /etc/systemd/system/gre-watch.service > /dev/null << 'EOF'
[Unit]
Description=GRE Tunnel Watchdog Service
After=gre.service
Requires=gre.service
BindsTo=gre.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/gre.sh check; sleep 30; done'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
6. ایجاد فایل لاگ
bash
sudo touch /var/log/gre-watch.log
sudo chmod 644 /var/log/gre-watch.log
7. فعال‌سازی و شروع سرویس‌ها
bash
# بارگذاری مجدد systemd
sudo systemctl daemon-reload

# فعال‌سازی سرویس‌ها
sudo systemctl enable gre.service
sudo systemctl enable gre-watch.service

# شروع سرویس‌ها
sudo systemctl start gre.service
sudo systemctl start gre-watch.service

# بررسی وضعیت
echo "🎉 Installation completed!"
sudo systemctl status gre.service --no-pager
🛠️ دستورات مدیریتی
بررسی وضعیت
bash
# وضعیت سرویس GRE
sudo systemctl status gre.service

# وضعیت Watchdog
sudo systemctl status gre-watch.service

# وضعیت تونل
sudo /usr/local/bin/gre.sh status

# مشاهده لاگ
sudo tail -f /var/log/gre-watch.log

# لاگ‌های systemd
sudo journalctl -u gre.service -f
کنترل سرویس
bash
# راه‌اندازی مجدد
sudo systemctl restart gre.service
sudo systemctl restart gre-watch.service

# توقف سرویس‌ها
sudo systemctl stop gre-watch.service
sudo systemctl stop gre.service

# شروع مجدد
sudo systemctl start gre.service
sudo systemctl start gre-watch.service
تست دستی
bash
# تست تونل
ping -c 4 10.10.10.1

# نمایش اطلاعات تونل
ip tunnel show gre1
ip addr show gre1
ip link show gre1

# تست اسکریپت
sudo /usr/local/bin/gre.sh status
sudo /usr/local/bin/gre.sh restart
⚙️ تنظیمات سرور مقابل
اگر روی سرور مقابل هم همین اسکریپت را نصب می‌کنید، تنظیمات زیر را معکوس کنید:

bash
# در سرور اول:
LOCAL_IP="103.45.246.176"
REMOTE_IP="89.44.242.102"
TUN_IP="10.10.10.2/30"
PING_TARGET="10.10.10.1"

# در سرور دوم:
LOCAL_IP="89.44.242.102"      # معکوس REMOTE_IP سرور اول
REMOTE_IP="103.45.246.176"    # معکوس LOCAL_IP سرور اول
TUN_IP="10.10.10.1/30"        # معکوس PING_TARGET سرور اول
PING_TARGET="10.10.10.2"      # معکوس TUN_IP سرور اول
🔧 تنظیم فایروال
bash
# اگر از iptables استفاده می‌کنید:
sudo iptables -A INPUT -p gre -j ACCEPT
sudo iptables -A FORWARD -p gre -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# اگر از firewalld استفاده می‌کنید:
sudo firewall-cmd --add-protocol=gre --permanent
sudo firewall-cmd --reload

# فعال‌سازی IP Forwarding:
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -
خب الان من اینو چه جوری بزارم توreadme.md
روش قرار دادن در README.md:
1. ابتدا فایل README.md را در ریشه پروژه ایجاد کنید:
bash
nano README.md
2. کل محتوای زیر را کپی کرده و در فایل پیست کنید:
markdown
# GRE Tunnel Auto Installer 🔗

یک اسکریپت کامل برای راه‌اندازی خودکار تونل GRE بین دو سرور لینوکس

## 🚀 نصب خودکار (توصیه شده)

```bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)
🔧 نصب دستی کامل
تمام دستورات زیر را به ترتیب کپی و اجرا کنید:

1. نصب پیش‌نیازها
bash
# برای Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y curl iproute2

# برای CentOS/RHEL
sudo yum install -y curl iproute
2. ایجاد اسکریپت اصلی
bash
sudo tee /usr/local/bin/gre.sh > /dev/null << 'EOF'
#!/bin/bash

# 🔧 تنظیمات شما - این قسمت را تغییر دهید
LOCAL_IP="103.45.246.176"      # IP عمومی سرور فعلی
REMOTE_IP="89.44.242.102"      # IP عمومی سرور مقابل
TUN_IP="10.10.10.2/30"         # IP تونل محلی (مثال: 10.10.10.2/30)
DEV="gre1"                     # نام اینترفیس تونل
PING_TARGET="10.10.10.1"       # IP تونل مقابل

case "$1" in
  start)
    echo "🚀 Starting GRE tunnel..."
    ip tunnel del $DEV 2>/dev/null
    ip tunnel add $DEV mode gre local $LOCAL_IP remote $REMOTE_IP ttl 255
    ip addr add $TUN_IP dev $DEV
    ip link set $DEV up
    echo "✅ GRE tunnel started successfully"
    ;;
  stop)
    echo "🛑 Stopping GRE tunnel..."
    ip link set $DEV down 2>/dev/null
    ip tunnel del $DEV 2>/dev/null
    echo "✅ GRE tunnel stopped"
    ;;
  restart)
    echo "🔄 Restarting GRE tunnel..."
    $0 stop
    sleep 2
    $0 start
    ;;
  check)
    ping -c 3 -W 2 $PING_TARGET >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') GRE tunnel is down, restarting..." >> /var/log/gre-watch.log
      $0 restart
    fi
    ;;
  status)
    echo "=== GRE Tunnel Status ==="
    ip tunnel show $DEV 2>/dev/null || echo "❌ Tunnel $DEV is not running"
    echo ""
    echo "=== Interface Status ==="
    ip addr show $DEV 2>/dev/null || echo "❌ Interface $DEV not found"
    echo ""
    echo "=== Routing Table ==="
    ip route | grep $DEV 2>/dev/null || echo "No routes found for $DEV"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|check|status}"
    exit 1
    ;;
esac
EOF
3. تنظیم مجوزهای اجرایی
bash
sudo chmod +x /usr/local/bin/gre.sh
4. ایجاد سرویس Systemd برای GRE
bash
sudo tee /etc/systemd/system/gre.service > /dev/null << 'EOF'
[Unit]
Description=GRE Tunnel Service
After=network.target
Wants=network.target
Requires=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre.sh start
ExecStop=/usr/local/bin/gre.sh stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
5. ایجاد سرویس Watchdog برای نظارت
bash
sudo tee /etc/systemd/system/gre-watch.service > /dev/null << 'EOF'
[Unit]
Description=GRE Tunnel Watchdog Service
After=gre.service
Requires=gre.service
BindsTo=gre.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/gre.sh check; sleep 30; done'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
6. ایجاد فایل لاگ
bash
sudo touch /var/log/gre-watch.log
sudo chmod 644 /var/log/gre-watch.log
7. فعال‌سازی و شروع سرویس‌ها
bash
# بارگذاری مجدد systemd
sudo systemctl daemon-reload

# فعال‌سازی سرویس‌ها
sudo systemctl enable gre.service
sudo systemctl enable gre-watch.service

# شروع سرویس‌ها
sudo systemctl start gre.service
sudo systemctl start gre-watch.service

# بررسی وضعیت
echo "🎉 Installation completed!"
sudo systemctl status gre.service --no-pager
🛠️ دستورات مدیریتی
بررسی وضعیت
bash
# وضعیت سرویس GRE
sudo systemctl status gre.service

# وضعیت Watchdog
sudo systemctl status gre-watch.service

# وضعیت تونل
sudo /usr/local/bin/gre.sh status

# مشاهده لاگ
sudo tail -f /var/log/gre-watch.log

# لاگ‌های systemd
sudo journalctl -u gre.service -f
کنترل سرویس
bash
# راه‌اندازی مجدد
sudo systemctl restart gre.service
sudo systemctl restart gre-watch.service

# توقف سرویس‌ها
sudo systemctl stop gre-watch.service
sudo systemctl stop gre.service

# شروع مجدد
sudo systemctl start gre.service
sudo systemctl start gre-watch.service
تست دستی
bash
# تست تونل
ping -c 4 10.10.10.1

# نمایش اطلاعات تونل
ip tunnel show gre1
ip addr show gre1
ip link show gre1

# تست اسکریپت
sudo /usr/local/bin/gre.sh status
sudo /usr/local/bin/gre.sh restart
⚙️ تنظیمات سرور مقابل
اگر روی سرور مقابل هم همین اسکریپت را نصب می‌کنید، تنظیمات زیر را معکوس کنید:

bash
# در سرور اول:
LOCAL_IP="103.45.246.176"
REMOTE_IP="89.44.242.102"
TUN_IP="10.10.10.2/30"
PING_TARGET="10.10.10.1"

# در سرور دوم:
LOCAL_IP="89.44.242.102"      # معکوس REMOTE_IP سرور اول
REMOTE_IP="103.45.246.176"    # معکوس LOCAL_IP سرور اول
TUN_IP="10.10.10.1/30"        # معکوس PING_TARGET سرور اول
PING_TARGET="10.10.10.2"      # معکوس TUN_IP سرور اول
🔧 تنظیم فایروال
bash
# اگر از iptables استفاده می‌کنید:
sudo iptables -A INPUT -p gre -j ACCEPT
sudo iptables -A FORWARD -p gre -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# اگر از firewalld استفاده می‌کنید:
sudo firewall-cmd --add-protocol=gre --permanent
sudo firewall-cmd --reload

# فعال‌سازی IP Forwarding:
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
📝 یادداشت‌های مهم
قبل از اجرا حتماً IPها را با مقادیر واقعی خود جایگزین کنید

هر دو سرور باید دسترسی به یکدیگر داشته باشند

پورت 47 (پروتکل GRE) باید در فایروال باز باشد

پس از نصب، نیازی به ریبوت سرور نیست

❓ راهنمایی
اگر با مشکل مواجه شدید:

bash
# بررسی خطاها
sudo journalctl -u gre.service --no-pager -n 50
sudo tail -n 50 /var/log/gre-watch.log

# تست اتصال
ping -c 4 [REMOTE_IP]

# ریستارت کامل
sudo systemctl daemon-reload
sudo systemctl restart gre.service gre-watch.service
