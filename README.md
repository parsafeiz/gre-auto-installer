# 🌐 GRE Tunnel Auto Installer

![Shell](https://img.shields.io/badge/Shell-Bash-green)
![Linux](https://img.shields.io/badge/OS-Linux-blue)
![Systemd](https://img.shields.io/badge/Service-systemd-orange)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

راه‌اندازی **تونل GRE پایدار و خودکار** بین دو سرور (ایران ↔ خارج)  
مناسب برای بک‌هال، V2Ray، Xray و سناریوهای مشابه.

---

## ✨ ویژگی‌ها

| قابلیت | توضیح |
|------|------|
| 🚀 نصب سریع | نصب کامل با یک دستور |
| 🔁 Auto Restart | ریستارت خودکار در صورت قطع تونل |
| 🛡 Watchdog | مانیتورینگ با ping |
| 🔄 Persist | اجرای خودکار بعد از ریبوت |
| ⚙️ systemd | کاملاً استاندارد و پایدار |

---

## 🚀 نصب اتوماتیک (پیشنهادی)

با اجرای دستور زیر، همه‌چیز به‌صورت خودکار نصب و فعال می‌شود:

```bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)






nano /usr/local/bin/gre.sh

nano /usr/local/bin/gre.sh
#!/bin/bash

LOCAL_IP="IP_LOCAL_SERVER"
REMOTE_IP="IP_REMOTE_SERVER"
TUN_IP="10.10.10.2/30"
PING_TARGET="10.10.10.1"
DEV="gre1"

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
esac
