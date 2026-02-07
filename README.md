# GRE Tunnel Auto Installer 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/Bash-Script-green.svg)](https://www.gnu.org/software/bash/)
[![Systemd](https://img.shields.io/badge/Systemd-Service-red.svg)](https://systemd.io/)

یک اسکریپت کامل برای راه‌اندازی تونل GRE بین دو سرور لینوکس

---

## 📖 فهرست مطالب
- [🎯 معرفی](#معرفی)
- [📦 نصب خودکار](#نصب-خودکار)
- [🔧 نصب دستی](#نصب-دستی)
  - [1️⃣ نصب پیش‌نیازها](#1-نصب-پیشنیازها)
  - [2️⃣ ایجاد اسکریپت GRE](#2-ایجاد-اسکریپت-gre)
  - [3️⃣ تنظیم مجوزها](#3-تنظیم-مجوزها)
  - [4️⃣ ایجاد سرویس Systemd](#4-ایجاد-سرویس-systemd)
  - [5️⃣ ایجاد سرویس Watchdog](#5-ایجاد-سرویس-watchdog)
  - [6️⃣ فعال‌سازی سرویس‌ها](#6-فعالسازی-سرویسها)
- [⚙️ پیکربندی](#پیکربندی)
- [🛠️ مدیریت](#مدیریت)
- [🔍 عیب‌یابی](#عیبیابی)
- [❓ سوالات متداول](#سوالات-متداول)

---

## 🎯 معرفی <a id="معرفی"></a>
این پروژه راه‌اندازی تونل GRE بین دو سرور لینوکس را ساده می‌کند.

### ✨ ویژگی‌ها
- ✅ راه‌اندازی سریع با یک دستور
- ✅ سرویس Systemd برای مدیریت خودکار
- ✅ Watchdog برای نظارت بر اتصال
- ✅ لاگ‌گیری کامل

---

## 📦 نصب خودکار <a id="نصب-خودکار"></a>

برای نصب سریع و خودکار:

```bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)
🔧 نصب دستی <a id="نصب-دستی"></a>
1️⃣ نصب پیش‌نیازها <a id="1-نصب-پیشنیازها"></a>
bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y curl iproute2

# CentOS/RHEL
sudo yum install -y curl iproute
2️⃣ ایجاد اسکریپت GRE <a id="2-ایجاد-اسکریپت-gre"></a>
bash
sudo nano /usr/local/bin/gre.sh
کد زیر را کپی و در فایل قرار دهید:

bash
#!/bin/bash

# ⚠️ تنظیمات خود را اینجا وارد کنید
LOCAL_IP="103.45.246.176"
REMOTE_IP="89.44.242.102"
TUN_IP="10.10.10.2/30"
DEV="gre1"
PING_TARGET="10.10.10.1"

case "$1" in
  start)
    ip tunnel del $DEV 2>/dev/null
    ip tunnel add $DEV mode gre local $LOCAL_IP remote $REMOTE_IP ttl 255
    ip addr add $TUN_IP dev $DEV
    ip link set $DEV up
    ;;
  stop)
    ip link set $DEV down 2>/dev/null
    ip tunnel del $DEV 2>/dev/null
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  check)
    ping -c 3 -W 2 $PING_TARGET >/dev/null
    if [ $? -ne 0 ]; then
      echo "$(date) GRE down, restarting..." >> /var/log/gre-watch.log
      $0 restart
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|check}"
    exit 1
    ;;
esac
ذخیره: Ctrl+X → Y → Enter

3️⃣ تنظیم مجوزها <a id="3-تنظیم-مجوزها"></a>
bash
sudo chmod +x /usr/local/bin/gre.sh
4️⃣ ایجاد سرویس Systemd <a id="4-ایجاد-سرویس-systemd"></a>
bash
sudo nano /etc/systemd/system/gre.service
کد زیر را قرار دهید:

ini
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
5️⃣ ایجاد سرویس Watchdog <a id="5-ایجاد-سرویس-watchdog"></a>
bash
sudo nano /etc/systemd/system/gre-watch.service
کد زیر را قرار دهید:

ini
[Unit]
Description=GRE Ping Watchdog
After=gre.service

[Service]
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/gre.sh check; sleep 10; done'
Restart=always

[Install]
WantedBy=multi-user.target
6️⃣ فعال‌سازی سرویس‌ها <a id="6-فعالسازی-سرویسها"></a>
bash
# ایجاد فایل لاگ
sudo touch /var/log/gre-watch.log

# بارگذاری سرویس‌ها
sudo systemctl daemon-reload

# فعال‌سازی
sudo systemctl enable gre.service
sudo systemctl enable gre-watch.service

# شروع سرویس‌ها
sudo systemctl start gre.service
sudo systemctl start gre-watch.service

# بررسی وضعیت
sudo systemctl status gre.service
⚙️ پیکربندی <a id="پیکربندی"></a>
تنظیمات سرور مقابل
bash
# سرور اول
LOCAL_IP="103.45.246.176"
REMOTE_IP="89.44.242.102"
TUN_IP="10.10.10.2/30"
PING_TARGET="10.10.10.1"

# سرور دوم
LOCAL_IP="89.44.242.102"
REMOTE_IP="103.45.246.176"
TUN_IP="10.10.10.1/30"
PING_TARGET="10.10.10.2"
🛠️ مدیریت <a id="مدیریت"></a>
دستورات مفید
bash
# بررسی وضعیت
sudo systemctl status gre.service
sudo systemctl status gre-watch.service

# کنترل سرویس
sudo systemctl start gre.service
sudo systemctl stop gre.service
sudo systemctl restart gre.service

# مشاهده لاگ
sudo tail -f /var/log/gre-watch.log
sudo journalctl -u gre.service -f
🔍 عیب‌یابی <a id="عیبیابی"></a>
مشکلات رایج
تونل وصل نمی‌شود

bash
ping -c 4 103.45.246.176
ip tunnel show gre1
Watchdog کار نمی‌کند

bash
sudo journalctl -u gre-watch.service -f
sudo tail -f /var/log/gre-watch.log
❓ سوالات متداول <a id="سوالات-متداول"></a>
❓ چگونه تونل را حذف کنم؟
bash
sudo systemctl stop gre-watch.service
sudo systemctl stop gre.service
sudo systemctl disable gre-watch.service gre.service
