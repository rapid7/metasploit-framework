# Jenkins Enumeration Auxiliary Module

## Vulnerable Application
This module performs unauthenticated enumeration on Jenkins servers. It attempts to discover the Jenkins version, identify unauthenticated accessible endpoints, and gather useful system information when possible.

Jenkins servers that do not enforce strict authentication on certain URLs (such as `/script`) are susceptible to this enumeration. This module helps penetration testers quickly identify such information leakage.
Jenkins instances may expose sensitive information through misconfigured endpoints. Many companies unintentionally leave URLs like /script and /manage open without authentication, allowing attackers to retrieve system details. If these endpoints return data, it’s a sign that authentication settings might need to be tightened.


## Verification Steps
1. Start `msfconsole`
2. Use the module: `use auxiliary/scanner/http/jenkins_enum`
3. Set the target(s) and other options: `set RHOSTS <target IP or CIDR>`, `set RPORT 8080`, `set TARGETURI /jenkins/`, etc
4. Run the module: `run`
5. You might see output similar to:

``` 
[+] 192.168.1.100:8080 - Jenkins Version: 2.319.1
[+] 192.168.1.100:8080 - /script is accessible without authentication (HTTP 200)
[+] 192.168.1.100:8080 - Enumerating plugins...
[+] 192.168.1.100:8080 - Plugin detected: Git Plugin 4.11.3
[+] 192.168.1.100:8080 - System Information:
    OS: Linux
    OS Version: 5.4.0-77-generic
    Architecture: amd64
    Jenkins Home: /var/lib/jenkins
[*] 192.168.1.100:8080 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Options

### RHOSTS
Specifies the target host(s) or IP range to scan. You can input a single IP address, a range, or a CIDR subnet.
Default: None (required)

### RPORT
Defines the target port for HTTP connections. Jenkins often runs on port 8080, but the default for this module is 80. Adjust accordingly.
Default: 80

### TARGETURI
The base path of the Jenkins application on the target server. Usually /jenkins/ but can differ based on installation or proxy setup.
Default: /jenkins/

### THREADS
The number of concurrent threads to use for faster scanning. Increasing this number can speed up scans but may generate more network traffic or load on the target.
Default: 1

### VHOST
Specify a virtual host name for the HTTP Host header if Jenkins is running behind a virtual host or reverse proxy.
Default: None

## Scenarios
This example demonstrates how to use the jenkins_enum module to enumerate information from a Jenkins server running on the local network at IP 192.168.1.100 on port 8080, where Jenkins is installed at the default /jenkins/ path.

```
msf6 > use auxiliary/scanner/http/jenkins_enum
msf6 auxiliary(scanner/http/jenkins_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/jenkins_enum) > set RPORT 8080
msf6 auxiliary(scanner/http/jenkins_enum) > set TARGETURI /jenkins/
msf6 auxiliary(scanner/http/jenkins_enum) > run

[*] 192.168.1.100:8080 - Jenkins Version: 2.319.1
[+] 192.168.1.100:8080 - /script is accessible without authentication (HTTP 200)
[*] 192.168.1.100:8080 - Enumerating plugins...
[+] 192.168.1.100:8080 - Plugin detected: Git Plugin 4.11.3
[+] 192.168.1.100:8080 - Plugin detected: Matrix Authorization Strategy 2.6.7
[+] 192.168.1.100:8080 - Plugin detected: Workflow CPS 2.92
[*] 192.168.1.100:8080 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
The module retrieves the Jenkins version and installed plugins without requiring credentials, which can help identify vulnerable plugin versions or configuration weaknesses.
