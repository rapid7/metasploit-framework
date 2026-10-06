## Vulnerable Application

This module checks for known vulnerabilities in the CGI applications of Supermicro Onboard IPMI controllers. These issues include several unauthenticated buffer overflows in the login.cgi and close_window.cgi components, which can lead to remote code execution.

The vulnerabilities affect Supermicro Onboard IPMI controllers with firmware versions prior to SMT_X9_215.

### Installation

Supermicro IPMI controllers are embedded in Supermicro server motherboards. For testing purposes, you can use a Docker container to simulate a vulnerable web server:

```bash
# Create a directory for the vulnerable app
mkdir -p supermicro_ipmi
cd supermicro_ipmi

# Create a simple Flask app that mimics the vulnerable behavior
cat > app.py << 'EOF'
from flask import Flask, request, Response
import sys

app = Flask(__name__)

@app.route('/')
def index():
    return '''<html><head><title>IPMI</title></head>
    <body>ATEN International Co Ltd.</body></html>'''

@app.route('/cgi/login.cgi', methods=['POST'])
def login():
    name = request.form.get('name', '')
    if len(name) > 250:
        return Response('Internal Server Error', status=500)
    return '''<html><body>ATEN International Co Ltd.
    <script>top.location.href = location.href;</script></body></html>'''

@app.route('/cgi/close_window.cgi', methods=['POST'])
def close_window():
    sess = request.form.get('sess_sid', '')
    if len(sess) > 100:
        return Response('Internal Server Error', status=500)
    return "Can't find action"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
EXPOSE 80
CMD ["python", "app.py"]
EOF

# Build and run
docker build -t vulnerable-ipmi .
docker run -d -p 80:80 --name ipmi vulnerable-ipmi
```

## Verification Steps

1. Install and configure the vulnerable application as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/smt_ipmi_cgi_scanner`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see output indicating which vulnerabilities are present

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 80)

**THREADS**

The number of concurrent threads (default: 1)

**VHOST**

HTTP server virtual host

## Scenarios

### Scanning a Vulnerable Supermicro IPMI Controller

```
msf6 > use auxiliary/scanner/http/smt_ipmi_cgi_scanner
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > run

[*] Checking if it's a Supermicro IPMI web interface...
[+] Supermicro IPMI web interface found
[*] Checking CVE-2013-3621 (login.gi Buffer Overflow) ...
[+] Vulnerable to CVE-2013-3621 (login.cgi Buffer Overflow)
[*] Checking CVE-2013-3623 (close_window.gi Buffer Overflow) ...
[+] Vulnerable to CVE-2013-3623 (close_window.cgi Buffer Overflow)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple Hosts

```
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/http/smt_ipmi_cgi_scanner) > run

[+] 192.0.2.10:80 - Vulnerable to CVE-2013-3621 (login.cgi Buffer Overflow)
[+] 192.0.2.10:80 - Vulnerable to CVE-2013-3623 (close_window.cgi Buffer Overflow)
[+] 192.0.2.15:80 - Vulnerable to CVE-2013-3621 (login.cgi Buffer Overflow)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
