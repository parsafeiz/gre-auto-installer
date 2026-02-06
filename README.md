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


