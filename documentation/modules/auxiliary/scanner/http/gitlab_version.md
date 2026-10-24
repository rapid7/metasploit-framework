## Vulnerable Application

This module scans a GitLab installation to identify its version information. GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager with features like issue tracking, continuous integration, and deployment pipeline capabilities.

The module extracts version information from publicly accessible GitLab endpoints and can identify both Community Edition (CE) and Enterprise Edition (EE) installations.

### Installation

You can set up a GitLab instance using Docker:

```bash
# Run GitLab Community Edition
docker run -d \
  --hostname gitlab.example.com \
  --name gitlab \
  -p 80:80 -p 443:443 -p 22:22 \
  gitlab/gitlab-ce:14.0.0-ce.0

# Wait for GitLab to initialize (this can take several minutes)
docker logs -f gitlab

# GitLab will be accessible at http://localhost
```

For a specific version:

```bash
# GitLab 13.12.0 CE
docker run -d \
  --hostname gitlab.local \
  --name gitlab-13 \
  -p 8080:80 \
  gitlab/gitlab-ce:13.12.0-ce.0

# GitLab 15.0.0 EE
docker run -d \
  --hostname gitlab.local \
  --name gitlab-ee \
  -p 8081:80 \
  gitlab/gitlab-ee:15.0.0-ee.0
```

Using docker-compose for a full setup:

```bash
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  gitlab:
    image: gitlab/gitlab-ce:14.0.0-ce.0
    hostname: gitlab.example.com
    ports:
      - "8080:80"
      - "8443:443"
      - "2222:22"
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://gitlab.example.com:8080'
        gitlab_rails['gitlab_shell_ssh_port'] = 2222
    volumes:
      - gitlab_config:/etc/gitlab
      - gitlab_logs:/var/log/gitlab
      - gitlab_data:/var/opt/gitlab
    restart: unless-stopped

volumes:
  gitlab_config:
  gitlab_logs:
  gitlab_data:
EOF

docker-compose up -d
```

## Verification Steps

1. Install and configure GitLab as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/gitlab_version`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. The module will display the GitLab version range

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 80)

**SSL**

Negotiate SSL/TLS for outgoing connections (default: false)

**TARGETURI**

The base path to GitLab (default: `/`)

**VHOST**

HTTP server virtual host

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Scanning a GitLab Community Edition Instance

```
msf6 > use auxiliary/scanner/http/gitlab_version
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.10:80: 14.0.0-ce -> 14.0.12-ce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a GitLab Enterprise Edition Instance

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.15
RHOSTS => 192.0.2.15
msf6 auxiliary(scanner/http/gitlab_version) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/gitlab_version) > set SSL true
SSL => true
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.15:443: 15.0.0-ee -> 15.0.5-ee
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple GitLab Instances

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/http/gitlab_version) > set THREADS 20
THREADS => 20
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.10:80: 14.0.0-ce -> 14.0.12-ce
[+] Gitlab version range for 192.0.2.15:80: 13.12.0-ce -> 13.12.15-ce
[+] Gitlab version range for 192.0.2.20:80: 15.5.0-ee -> 15.5.7-ee
[-] Unable to find Gitlab version for 192.0.2.25.
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning GitLab on a Non-Standard Port

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/gitlab_version) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.10:8080: 14.0.0-ce -> 14.0.12-ce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning with Custom Target URI

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/gitlab_version) > set TARGETURI /gitlab/
TARGETURI => /gitlab/
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.10:80: 13.8.0-ce -> 13.8.8-ce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Unable to Detect GitLab

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.100
RHOSTS => 192.0.2.100
msf6 auxiliary(scanner/http/gitlab_version) > run

[-] Unable to find Gitlab version for 192.0.2.100.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Verifying Database Storage

After a successful scan, you can verify the stored information in the Metasploit database:

```
msf6 auxiliary(scanner/http/gitlab_version) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/http/gitlab_version) > run

[+] Gitlab version range for 192.0.2.10:80: 14.0.0-ce -> 14.0.12-ce
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/http/gitlab_version) > notes

[*] Time: 2026-10-06 12:30:45 UTC Note: host=192.0.2.10 type=gitlab.version data={:version=>["14.0.0-ce", "14.0.12-ce"]}
```
