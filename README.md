# **NSA (Network Security Assistant) Toolkit**

**Creator:** Yousuf Alkhanjari

A powerful, all-in-one, menu-driven Bash script designed to manage and enhance the defensive security and privacy of a Linux system.

### **Philosophy**

The NSA Toolkit was created to bridge the gap between powerful, complex command-line security tools and the everyday user. Security should be accessible to everyone. This script takes a suite of best-in-class open-source security software and centralizes them into a single, user-friendly interface that empowers users to take control of their system's defense.

### **What It Is For**

This toolkit is designed for any Linux user who wants to:

* **Harden** their system against common threats.  
* **Protect** their privacy on untrusted networks.  
* **Monitor** their system for suspicious activity.  
* **Automate** routine security checks and receive alerts.  
* **Manage** users, firewalls, and data security from one place.  
* **Learn** more about their system's security posture.

### **Key Features**

The toolkit is organized into several powerful modules:

#### **🛡️ Proactive Defense & Hardening**

* **Firewall Management:** Easy-to-use interface for UFW (Uncomplicated Firewall) to set rules, enable/disable, and block threats.  
* **Antivirus Management:** Integrates ClamAV for on-demand file scanning and deep system scans.  
* **Automated Security Bot:** A cron-based bot that runs hourly checks for new malware in downloads and brute-force login attempts, creating actionable alerts.  
* **Threat Intelligence:**  
  * **Hosts File Blocking:** Downloads and installs a master hosts file to block thousands of ad, malware, and tracking domains.  
  * **Browser History Scanner:** Scans Firefox and Chrome/Chromium history for visits to known malicious sites.  
* **System Updates:** A simple one-command option to update, upgrade, and clean your system packages.

#### **🕵️ Anonymity & Privacy**

* **VPN Management:** Start/stop OpenVPN connections and download configurations from a URL.  
* **VPN Kill Switch:** Instantly create a firewall kill switch that blocks all traffic if the VPN disconnects.  
* **Tor Integration:** An "Anonsurf"-style mode to route all system traffic through the Tor network for maximum anonymity.  
* **MAC Address Changer:** Randomize or reset your network card's MAC address to prevent tracking on local networks.

#### **📊 Monitoring & Reporting**

* **Live Monitoring Hub:** Open separate, dedicated terminal windows to watch live logs for the firewall, user logins, system events, and bot activity without interrupting your workflow.  
* **Security Reports:** Generate historical reports on firewall blocks, successful logins, and failed login attempts to identify patterns and potential threats.  
* **Automated CSV Reporting:** An optional bot that generates CSV reports of firewall blocks and failed logins every 5 minutes for easy analysis.  
* **Quick Status Dashboard:** An all-in-one dashboard showing your public IP, firewall status, pending updates, internet speed, disk usage, and more.

#### **⚙️ System & User Management**

* **Full User Management:** A secure, multi-user login system. Admins can add, delete, and change the privilege level (user/admin) of other users.  
* **Bot Management System:** A dedicated menu for admins to create new scheduled bots (network scans, file scans), list all active bots, delete bots, and even edit the bot source code.  
* **Secure Backup & Restore:** Create an encrypted backup of all users and settings, which can be restored at any time.

### **Installation**

The script is designed to be self-contained and easy to set up.

1. **Clone the repository:**  
   git clone \[https://github.com/ghox789/NSA-Security-Toolkit.git\](https://github.com/ghox789/NSA-Security-Toolkit.git)

2. **Navigate into the directory:**  
   cd NSA-Security-Toolkit

3. **Make the script executable:**  
   chmod \+x nsa.sh

### **How to Use**

1. **Run the script:**  
   ./nsa.sh

2. **First-Time Setup:**  
   * The script will detect if it's the first time being run.  
   * It will check for all required software packages and ask for your permission to install any that are missing.  
   * It will then guide you through an initial setup for the firewall and antivirus database.  
   * Finally, it will prompt you to create the initial **admin** user account.  
3. **Login:** After the first run, you will always be greeted by a secure login prompt.  
4. **Navigate the Menus:** Simply use the number keys to navigate through the various tools and options.

### **Disclaimer**

This tool is designed for **defensive and educational purposes only**. The creator, Yousuf Alkhanjari, is not responsible for any misuse of this script. Always have backups of your important data and use these powerful tools responsibly.
=======
NSA (Network Security Assistant) Toolkit
Creator: Yousuf Alkhanjari
A powerful, all-in-one, menu-driven Bash script designed to manage and enhance the defensive security and privacy of a Linux system.
Philosophy
The NSA Toolkit was created to bridge the gap between powerful, complex command-line security tools and the everyday user. Security should be accessible to everyone. This script takes a suite of best-in-class open-source security software and centralizes them into a single, user-friendly interface that empowers users to take control of their system's defense.
What It Is For
This toolkit is designed for any Linux user who wants to:
Harden their system against common threats.
Protect their privacy on untrusted networks.
Monitor their system for suspicious activity.
Automate routine security checks and receive alerts.
Manage users, firewalls, and data security from one place.
Learn more about their system's security posture.
Key Features
The toolkit is organized into several powerful modules:
🛡️ Proactive Defense & Hardening
Firewall Management: Easy-to-use interface for UFW (Uncomplicated Firewall) to set rules, enable/disable, and block threats.
Antivirus Management: Integrates ClamAV for on-demand file scanning and deep system scans.
Automated Security Bot: A cron-based bot that runs hourly checks for new malware in downloads and brute-force login attempts, creating actionable alerts.
Threat Intelligence:
Hosts File Blocking: Downloads and installs a master hosts file to block thousands of ad, malware, and tracking domains.
Browser History Scanner: Scans Firefox and Chrome/Chromium history for visits to known malicious sites.
System Updates: A simple one-command option to update, upgrade, and clean your system packages.
🕵️ Anonymity & Privacy
VPN Management: Start/stop OpenVPN connections and download configurations from a URL.
VPN Kill Switch: Instantly create a firewall kill switch that blocks all traffic if the VPN disconnects.
Tor Integration: An "Anonsurf"-style mode to route all system traffic through the Tor network for maximum anonymity.
MAC Address Changer: Randomize or reset your network card's MAC address to prevent tracking on local networks.
📊 Monitoring & Reporting
Live Monitoring Hub: Open separate, dedicated terminal windows to watch live logs for the firewall, user logins, system events, and bot activity without interrupting your workflow.
Security Reports: Generate historical reports on firewall blocks, successful logins, and failed login attempts to identify patterns and potential threats.
Automated CSV Reporting: An optional bot that generates CSV reports of firewall blocks and failed logins every 5 minutes for easy analysis.
Quick Status Dashboard: An all-in-one dashboard showing your public IP, firewall status, pending updates, internet speed, disk usage, and more.
⚙️ System & User Management
Full User Management: A secure, multi-user login system. Admins can add, delete, and change the privilege level (user/admin) of other users.
Bot Management System: A dedicated menu for admins to create new scheduled bots (network scans, file scans), list all active bots, delete bots, and even edit the bot source code.
Secure Backup & Restore: Create an encrypted backup of all users and settings, which can be restored at any time.
Installation
The script is designed to be self-contained and easy to set up.
Clone the repository:
git clone [https://github.com/ghox789/NSA-Security-Toolkit.git](https://github.com/ghox789/NSA-Security-Toolkit.git)


Navigate into the directory:
cd NSA-Security-Toolkit


Make the script executable:
chmod +x nsa.sh


How to Use
Run the script:
./nsa.sh


First-Time Setup:
The script will detect if it's the first time being run.
It will check for all required software packages and ask for your permission to install any that are missing.
It will then guide you through an initial setup for the firewall and antivirus database.
Finally, it will prompt you to create the initial admin user account.
Login: After the first run, you will always be greeted by a secure login prompt.
Navigate the Menus: Simply use the number keys to navigate through the various tools and options.
Disclaimer
This tool is designed for defensive and educational purposes only. The creator, Yousuf Alkhanjari, is not responsible for any misuse of this script. Always have backups of your important data and use these powerful tools responsibly.
