# GRE Tunnel Auto Installer 🔗

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Bash Script](https://img.shields.io/badge/Bash-Script-green.svg)](https://www.gnu.org/software/bash/)
[![Systemd Service](https://img.shields.io/badge/Systemd-Service-red.svg)](https://systemd.io/)

یک اسکریپت کامل برای راه‌اندازی خودکار تونل GRE بین دو سرور لینوکس با Systemd Service و Watchdog

---

## 📌 فهرست مطالب
- [🚀 نصب خودکار (یک خطی)](#-نصب-خودکار-یک-خطی)
- [🔧 نصب دستی کامل](#-نصب-دستی-کامل)
- [⚙️ پیکربندی](#️-پیکربندی)
- [🛠️ دستورات مدیریتی](#️-دستورات-مدیریتی)
- [🔍 عیب‌یابی](#-عیبیابی)
- [❓ سوالات متداول](#-سوالات-متداول)
- [📞 پشتیبانی](#-پشتیبانی)

---

## 🚀 نصب خودکار (یک خطی)

**تنها با یک دستور همه چیز نصب می‌شود:**

```bash
bash <(curl -s https://raw.githubusercontent.com/parsafeiz/gre-auto-installer/main/gre-installer.sh)
