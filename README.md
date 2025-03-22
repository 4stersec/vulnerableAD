# Active Directory Vulnerable Lab Setup

## ⚠️ Disclaimer
🚨 **WARNING: This script is for research and educational purposes only!**
- DO NOT run this script in a production environment.
- This script intentionally weakens security settings to simulate vulnerabilities in **Active Directory (AD)**.
- **Use at your own risk** in a controlled lab environment.

---

## 🎯 Overview
This PowerShell script is designed to create a **deliberately vulnerable Active Directory environment** for penetration testing, red teaming, and CTF labs. It automates the process of **disabling security features, creating weak accounts, and enabling common AD misconfigurations** to help security professionals test attack techniques.

### 🔥 Features:
✅ Disables **Windows Defender, Firewall & AV Protections**  
✅ Enables **NTLMv1 & Disables SMB Signing** (Weak Authentication)  
✅ Creates **50+ Vulnerable AD Users** with weak passwords  
✅ Disables **Kerberos Pre-authentication** for easy credential attacks  
✅ Enables **Unconstrained Delegation** (Privilege Escalation)  
✅ Adds a **Group to Domain Admins** (Privilege Escalation)  
✅ Disables **LAPS** (Local Admin Password Solution)  
✅ Enables **Print Spooler Service** (PrintNightmare Attack Vector)  
✅ Weakens **GPO Policies** (GPO Hijacking)  
✅ Allows **Anonymous LDAP Queries** (User Enumeration)  
✅ Disables **SMB Signing** (NTLM Relay Exploitation)  
✅ Enables **SID History Injection** (Stealthy Privilege Escalation)  
✅ Creates a **Fake Admin Account** for **DCSync & DCShadow attacks**  




https://github.com/user-attachments/assets/f51d3488-fda0-4404-9ae4-84946c50ce22

---

## 🚀 Setup Instructions
### **Step 1: Run the Script**
Open **PowerShell as Administrator** and execute:
```powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force
.
```
```powershell
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/4stersec/vulnerableAD/refs/heads/main/VulnAD.ps1')
```

### **Step 2: Verify AD Vulnerabilities**
After execution, you can test the following:
- **Mimikatz** for credential extraction
- **Responder** for NTLM relay attacks
- **BloodHound** for attack path enumeration
- **Kerberoasting & ASREPRoasting**

---

## 🛑 Reverting Changes
To restore security settings, manually reset configurations or restore from a secure backup.

---

## 📜 Legal Notice
This script is intended for **authorized security research, training, and CTF challenges**. The author is **not responsible for any misuse or illegal activity** conducted with this script.

---

## 🔗 Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Active Directory Security Best Practices](https://adsecurity.org/)

---

## 🤝 Contributing
If you have improvements, feel free to submit a pull request!

📢 **Follow me on LinkedIn:** [Your LinkedIn Profile]  
💻 **GitHub:** [Your GitHub Profile]  

---

### 📌 Happy Hacking! 🔥

