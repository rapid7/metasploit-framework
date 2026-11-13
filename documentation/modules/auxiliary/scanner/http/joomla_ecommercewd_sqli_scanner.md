## Vulnerable Application

This module scans for hosts vulnerable to an unauthenticated SQL injection within the advanced search feature of the Web-Dorado ECommerce WD component for Joomla! version 1.2.5 and likely prior versions. The vulnerability exists in the `search_category_id` parameter.

### Installation

You can set up a vulnerable Joomla! installation with the ECommerce WD component:

```bash
# Create a vulnerable test environment
mkdir -p joomla_ecommerce_vuln
cd joomla_ecommerce_vuln

# Create a mock vulnerable endpoint
cat > app.py << 'EOF'
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

@app.route('/index.php', methods=['GET', 'POST'])
def index():
    option = request.args.get('option', '')
    controller = request.args.get('controller', '')
    task = request.args.get('task', '')
    
    if option == 'com_ecommercewd' and controller == 'products' and task == 'displayproducts':
        search_category_id = request.form.get('search_category_id', '')
        
        # Simulate SQL injection vulnerability
        # Look for UNION SELECT with CONCAT containing hex markers
        if 'UNION' in search_category_id.upper() and 'CONCAT' in search_category_id.upper():
            # Extract hex values from the CONCAT statement
            hex_pattern = r'0x([0-9a-fA-F]+)'
            hex_matches = re.findall(hex_pattern, search_category_id)
            
            if len(hex_matches) >= 3:
                # Decode hex values and include them in response
                decoded = ''.join([bytes.fromhex(h).decode('utf-8', errors='ignore') for h in hex_matches])
                return f"<html><body>Products: {decoded}</body></html>", 200
        
        return "<html><body>No products found</body></html>", 200
    
    return "Joomla! Site", 200

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
docker build -t joomla-ecommerce-vuln .
docker run -d -p 80:80 --name joomla-vuln joomla-ecommerce-vuln
```

Alternatively, for a full Joomla! installation:

```bash
# Download Joomla 3.4
wget https://github.com/joomla/joomla-cms/releases/download/3.4.0/Joomla_3.4.0-Stable-Full_Package.tar.gz

# Extract to web directory
mkdir joomla
tar -xzf Joomla_3.4.0-Stable-Full_Package.tar.gz -C joomla/

# Install ECommerce WD 1.2.5 component (vulnerable version)
# Download from Web-Dorado archive and install via Joomla admin interface

# Or use a docker-compose setup:
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  joomla:
    image: joomla:3.4
    ports:
      - "80:80"
    environment:
      JOOMLA_DB_HOST: mysql
      JOOMLA_DB_PASSWORD: joomla
    volumes:
      - joomla_data:/var/www/html
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: joomla
      MYSQL_DATABASE: joomla
      MYSQL_USER: joomla
      MYSQL_PASSWORD: joomla
    volumes:
      - mysql_data:/var/lib/mysql
volumes:
  joomla_data:
  mysql_data:
EOF

docker-compose up -d
```

## Verification Steps

1. Install and configure the vulnerable Joomla! site with ECommerce WD component as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see output indicating whether the site is vulnerable

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 80)

**TARGETURI**

The path to the Joomla install (default: `/`)

**SSL**

Negotiate SSL/TLS for outgoing connections (default: false)

**VHOST**

HTTP server virtual host

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Scanning a Vulnerable Joomla! Site

```
msf6 > use auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > run

[+] Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning with Custom Target URI

```
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set TARGETURI /joomla/
TARGETURI => /joomla/
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > run

[+] Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple Hosts

```
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > run

[+] 192.0.2.10:80 - Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)
[+] 192.0.2.15:80 - Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning with HTTPS

```
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set SSL true
SSL => true
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > run

[+] Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a Non-Vulnerable Site

```
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set RHOSTS 192.0.2.50
RHOSTS => 192.0.2.50
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/joomla_ecommercewd_sqli_scanner) > run

[-] Server did not respond in an expected way
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
