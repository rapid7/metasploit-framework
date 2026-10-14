## Vulnerable Application

This module checks for a static SSL certificate shipped with Supermicro Onboard IPMI controllers. An attacker with access to the publicly-available firmware can extract the private key and perform man-in-the-middle attacks or offline decryption of communication to the controller.

The vulnerability affects Supermicro Onboard IPMI (X9SCL/X9SCM) controllers with firmware version SMT_X9_214 and earlier versions.

### Installation

For testing purposes, you can create a web server with the static certificate:

```bash
mkdir -p supermicro_ssl
cd supermicro_ssl

# Create the static private key (from the module)
cat > server.key << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC1q1kR6chWLfwspD84Asyy6EFV6SYRGy/gILsYGtn9kCQi2RFo
bNxS5CvphbGWn9D9n5gJpTVWLWb3LwJxGuBKSRj2wrHLlejzw6kSmF+3xFCuMfxV
FSj8TM8JqlOqM1c6lvH2MSXnN7pJBVcekNKbBUEfptakPSejStljbXecSwIDAQAB
AoGAah4/FzGiboTKCyGeNA+eltsIXzCjpdZlrtwvrbLxpyXtldWKT59XS6ww4mXQ
CJYuNBhnbSrt7vrybG0vVfZHEOCvK+5YKBOtvRgrWDgs1Bkc5hsdI5gLx3jE7g6M
PuUvD7ueF4OzYeYRrOLWr957jl32n+hD/k65bKWAUp3aTDECQQDqnEPZWlmoH7Jp
6woRnEp+1cullHv8DviM5Huh+JeBotSa03p4unhKlRYSqnHdeHU2343n1VUDzvnV
LQWi5G+FAkEAxjt0S67lyuuVD842uZRHt2WSQvwt23aKzQ+EJwV0IXYzfefeLzEm
dDdvc1AJ31gweAQK89/5/1EEF40K7BJdjwJBAJDFdtTT/QlS7eyQPjlZwVp9IVp+
wvdqYZPHlkb/uLYlPZ6Aq01+e6ZCU0mXZgYtQ99lmhKaQQjFmsMiMh0va2UCQA2T
NLuaFpJ235ZdgNHknaSpiAKeUmWdEJRKY7poXTONbKlKn6SLsR50TWWQLZzl5SvS
2w0oYW5ile0m84CHIXECQQCrABn0HY4Ll9/4FX+OCWamqwENltU1GcGIogeyFymK
ZVX8QdAVoUiZoUaVku946j63WNSkI1sU/UWhL6XDt4gx
-----END RSA PRIVATE KEY-----
EOF

# Generate a certificate from this key
openssl req -new -x509 -key server.key -out server.crt -days 3650 -subj "/C=US/ST=CA/L=SanJose/O=ATEN International/CN=IPMI"

# Create a simple HTTPS server using Python
cat > https_server.py << 'EOF'
import http.server
import ssl

server_address = ('0.0.0.0', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.crt', 'server.key')

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Server running on https://0.0.0.0:443")
httpd.serve_forever()
EOF

# Run with sudo (required for port 443)
sudo python3 https_server.py
```

Using Docker:

```bash
cat > Dockerfile << 'EOF'
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY server.key server.crt https_server.py ./
EXPOSE 443
CMD ["python3", "https_server.py"]
EOF

docker build -t ipmi-static-cert .
docker run -d -p 443:443 --name ipmi-ssl ipmi-static-cert
```

## Verification Steps

1. Install and configure the vulnerable IPMI controller with static certificate as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/smt_ipmi_static_cert_scanner`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see output indicating whether the static certificate is present

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 443)

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Scanning a Vulnerable IPMI Controller with Static Certificate

```
msf6 > use auxiliary/scanner/http/smt_ipmi_static_cert_scanner
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > run

[+] 192.0.2.10:443 - Vulnerable to CVE-2013-3619 (Static SSL Certificate)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple Hosts

```
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set THREADS 20
THREADS => 20
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > run

[+] 192.0.2.10:443 - Vulnerable to CVE-2013-3619 (Static SSL Certificate)
[+] 192.0.2.15:443 - Vulnerable to CVE-2013-3619 (Static SSL Certificate)
[+] 192.0.2.20:443 - Vulnerable to CVE-2013-3619 (Static SSL Certificate)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a Non-Vulnerable Host

```
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set RHOSTS 192.0.2.50
RHOSTS => 192.0.2.50
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > run

[-] 192.0.2.50:443 - No certificate found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Custom Port Scanning

```
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > set RPORT 8443
RPORT => 8443
msf6 auxiliary(scanner/http/smt_ipmi_static_cert_scanner) > run

[+] 192.0.2.10:8443 - Vulnerable to CVE-2013-3619 (Static SSL Certificate)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
