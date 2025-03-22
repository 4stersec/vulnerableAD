<#
.SYNOPSIS
    This script weakens Active Directory security settings to simulate vulnerabilities for pentesting labs.
    
.WARNINGS
    - NEVER run this in a production environment. 
    - For research/CTF/hacking lab purposes only.
#>

Write-Host "Disabling Security Features & Making AD Vulnerable..." -ForegroundColor Red

# Dynamically retrieve the current domain
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$domainName = $domain.DNSRoot

Write-Host "[+] Detected Domain: $domainName ($domainDN)" -ForegroundColor Cyan

# Dynamically retrieve the first available server (or allow manual selection)
$servers = Get-ADComputer -Filter { OperatingSystem -like "*Server*" } -Property Name | Select-Object -ExpandProperty Name
if ($servers.Count -eq 0) {
    Write-Host "[-] No servers found in the domain. Please manually specify a server name." -ForegroundColor Red
    $serverName = Read-Host "Enter the server name"
} else {
    $serverName = $servers[0]  # Select the first server in the list
    Write-Host "[+] Selected Server: $serverName" -ForegroundColor Cyan
}

# 1️⃣ Disable Windows Defender & Security Features
Write-Host "[+] Disabling Windows Defender, Firewall & AV Protections..."
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# 2️⃣ Enable NTLMv1 & Disable SMB Signing (Weak Auth)
Write-Host "[+] Enabling NTLMv1 and Disabling SMB Signing..."
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 1 /f
    reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
} catch {
    Write-Host "Error modifying registry keys: $_" -ForegroundColor Yellow
}

# Function to generate random usernames
function Get-RandomUsername {
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    $username = ""
    for ($i = 1; $i -le 8; $i++) {
        $username += $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)]
    }
    return $username
}

# 3️⃣ Create 50 Vulnerable Users with Random Usernames
Write-Host "[+] Creating 50 Vulnerable Users with Random Usernames..."
for ($i = 1; $i -le 50; $i++) {
    $username = Get-RandomUsername
    $password = "Password$i!"
    try {
        $user = Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
        if (-not $user) {
            New-ADUser -Name $username -SamAccountName $username -UserPrincipalName "$username@$domainName" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PasswordNeverExpires $true -Enabled $true -ErrorAction Stop
            Write-Host "[+] Created user: ${username} with password: $password" -ForegroundColor Green
        } else {
            Write-Host "[-] User ${username} already exists. Skipping creation." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error creating user ${username}: $_" -ForegroundColor Red
    }
}

# 4️⃣ Disable Kerberos Pre-authentication for All Users
Write-Host "[+] Disabling Kerberos Pre-authentication for All Users..."
Get-ADUser -Filter { SamAccountName -like "vuln_*" } | ForEach-Object {
    $username = $_.SamAccountName
    try {
        Set-ADAccountControl -Identity $username -DoesNotRequirePreAuth $true
        Write-Host "[+] Disabled Kerberos pre-authentication for user: ${username}" -ForegroundColor Green
    } catch {
        Write-Host "Error modifying user ${username}: $_" -ForegroundColor Red
    }
}

# 5️⃣ Enable Unconstrained Delegation on Server
Write-Host "[+] Enabling Unconstrained Delegation on Server..."
try {
    $server = Get-ADComputer -Identity $serverName -ErrorAction SilentlyContinue
    if ($server) {
        Set-ADComputer -Identity $server -TrustedForDelegation $true
        Write-Host "[+] Enabled unconstrained delegation on server: $serverName" -ForegroundColor Green
    } else {
        Write-Host "[-] Server '$serverName' not found. Skipping unconstrained delegation." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error enabling unconstrained delegation: $_" -ForegroundColor Red
}

# 6️⃣ Add Group to Domain Admins (Privilege Escalation)
Write-Host "[+] Adding 'TestGroup' to Domain Admins..."
try {
    $group = Get-ADGroup -Filter { Name -eq "TestGroup" } -ErrorAction SilentlyContinue
    if (-not $group) {
        New-ADGroup -Name "TestGroup" -GroupScope Global -Path "CN=Users,$domainDN" -ErrorAction Stop
    }
    Add-ADGroupMember -Identity "Domain Admins" -Members "TestGroup" -ErrorAction Stop
    Write-Host "[+] Added 'TestGroup' to 'Domain Admins'." -ForegroundColor Green
} catch {
    Write-Host "Error adding group to Domain Admins: $_" -ForegroundColor Red
}

# 7️⃣ Disable LAPS (Local Admin Password Solution)
Write-Host "[+] Disabling LAPS & Setting Same Admin Password..."
try {
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" /v Enabled /t REG_DWORD /d 0 /f
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -ErrorAction Stop
    Write-Host "[+] Disabled LAPS and set local admin password." -ForegroundColor Green
} catch {
    Write-Host "Error setting local admin password: $_" -ForegroundColor Red
}

# 8️⃣ Enable Print Spooler (PrintNightmare)
Write-Host "[+] Enabling Print Spooler Service..."
try {
    Set-Service -Name Spooler -StartupType Automatic -ErrorAction Stop
    Start-Service Spooler -ErrorAction Stop
    Write-Host "[+] Enabled Print Spooler service." -ForegroundColor Green
} catch {
    Write-Host "Error enabling Print Spooler service: $_" -ForegroundColor Red
}

# 9️⃣ Create GPO with Weak Policies (Easy GPO Hijacking)
Write-Host "[+] Creating Weak Group Policy..."
try {
    $gpo = Get-GPO -Name "VulnerableGPO" -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name "VulnerableGPO" -ErrorAction Stop
    }
    Set-GPPermission -Name "VulnerableGPO" -PermissionLevel GpoEdit -TargetName "Authenticated Users" -TargetType Group -ErrorAction Stop
    Write-Host "[+] Created and configured 'VulnerableGPO'." -ForegroundColor Green
} catch {
    Write-Host "Error creating or setting GPO permissions: $_" -ForegroundColor Red
}

# 🔟 Set Machine Account Quota to 100 (For Account Takeover)
Write-Host "[+] Setting Machine Account Quota to 100..."
try {
    Set-ADDomain -Identity $domainDN -Replace @{"ms-DS-MachineAccountQuota"=100} -ErrorAction Stop
    Write-Host "[+] Set machine account quota to 100." -ForegroundColor Green
} catch {
    Write-Host "Error setting machine account quota: $_" -ForegroundColor Red
}

# 11️⃣ Create Weak SPN User (Kerberoasting)
Write-Host "[+] Creating Weak SPN User..."
try {
    $username = "kerberoast_user"
    $password = "Password123!"
    $user = Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
    if (-not $user) {
        New-ADUser -Name $username -SamAccountName $username -UserPrincipalName "$username@$domainName" -PasswordNeverExpires $true -Enabled $true -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -ErrorAction Stop
        Set-ADUser -Identity $username -ServicePrincipalNames @("MSSQLSvc/$username.$domainName")
        Write-Host "[+] Created SPN user: ${username} with password: $password" -ForegroundColor Green
    } else {
        Write-Host "[-] User ${username} already exists. Skipping creation." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error creating SPN user: $_" -ForegroundColor Red
}

# 12️⃣ Allow Anonymous LDAP Queries
Write-Host "[+] Enabling Anonymous LDAP Queries..."
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "Allow Anonymous Enumeration" /t REG_DWORD /d 1 /f
    Write-Host "[+] Enabled anonymous LDAP queries." -ForegroundColor Green
} catch {
    Write-Host "Error modifying registry key: $_" -ForegroundColor Red
}

# 13️⃣ Disable SMB Signing (NTLM Relay)
Write-Host "[+] Disabling SMB Signing for NTLM Relay..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RequireSecuritySignature -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name RequireSecuritySignature -Value 0
Write-Host "[+] Disabled SMB signing." -ForegroundColor Green

# 14️⃣ Allow SID History Injection (Privilege Escalation)
Write-Host "[+] Enabling SID History Injection..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TcpipClientSupport" -Value 1 -Type DWord
Write-Host "[+] Enabled SID history injection." -ForegroundColor Green

# 15️⃣ Create Fake Admin Accounts for DCSync & DCShadow Attacks
Write-Host "[+] Creating Fake Domain Admin Account..."
try {
    $username = "backup_admin"
    $password = "BackupP@ssw0rd!"
    $user = Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
    if (-not $user) {
        New-ADUser -Name $username -SamAccountName $username -UserPrincipalName "$username@$domainName" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Enabled $true -ErrorAction Stop
        Add-ADGroupMember -Identity "Domain Admins" -Members $username -ErrorAction Stop
        Write-Host "[+] Created fake admin account: ${username} with password: $password" -ForegroundColor Green
    } else {
        Write-Host "[-] User ${username} already exists. Skipping creation." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error creating fake admin account: $_" -ForegroundColor Red
}

Write-Host "✅ Active Directory Lab is Now Vulnerable! Happy Hacking!" -ForegroundColor Green
