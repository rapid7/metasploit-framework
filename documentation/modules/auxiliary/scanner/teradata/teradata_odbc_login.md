The teradata_odbc_login module is used to brute-force credentials for Teradata databases.

## Vulnerable Application

* Teradata Database
* Teradata Express

Teradata databases can be identified by scanning for TCP port 1025. An Nmap version scan can confirm if the service is recognized as Teradata.

## Extra Requirements

This module requires the Teradata ODBC driver and the Teradata python library.

### ODBC Driver for Kali Linux 2017.3
1. Download the Teradata ODBC driver for Ubuntu from [downloads.teradata.com](https://downloads.teradata.com/download/connectivity/odbc-driver/linux).
2. Refer to the Ubuntu package README for up-to-date instructions.
   1. Install **lib32stdc++6** if necessary.
   2. Install the ODBC drivers: `dpkg -i [package].deb`
   3. Copy **/opt/teradata/client/ODBC_64/odbc.ini** to **/root/.odbc.ini** .
      * Or your home directory if not root.
      * Make sure **odbc.ini** has been renamed to **.obdc.ini** .

### Configuration for OS X

On OS X the Python client needs to be pointed to the ODBC driver manually. Create `~/udaexec.ini` with the following contents:
```ini
[CONFIG]

odbcLibPath=/usr/lib/libiodbc.dylib
```

### Python Package
```
pip install teradata
```
## Verification Steps
1. Deploy a [Teradata Express](https://www.teradata.com/products-and-services/teradata-express) test environment.
2. Install the OBCD driver and python package.
3. Start msfconsole.
4. Do: `use auxiliary/scanner/teradata/teradata_odbc_login`
5. Do: `set RHOSTS [IPs]`
6. Do: `set USERNAME [username to try]`
7. Do: `set PASSWORD [password to try]`
   * The default Teradata credentials are the matching username and password 'dbc'.
8. Do: `run`

```
msf > use auxiliary/scanner/teradata/teradata_odbc_login
msf auxiliary(scanner/teradata/teradata_odbc_login) > set RHOSTS 192.168.0.2
RHOSTS => 192.168.0.2
msf auxiliary(scanner/teradata/teradata_odbc_login) > set USERNAME dbc
USERNAME => dbc
msf auxiliary(scanner/teradata/teradata_odbc_login) > set PASSWORD dbc
PASSWORD => dbc
msf auxiliary(scanner/teradata/teradata_odbc_login) > run

[*] Running for 192.168.0.2...
[*] 192.168.0.2:1025 - Creating connection: %s
[*] 192.168.0.2:1025 - Loading ODBC Library: %s
[*] 192.168.0.2:1025 - Method succeeded with info:  [26] 523 24
[*] 192.168.0.2:1025 - Method succeeded with info:  [26] 523 24
[*] 192.168.0.2:1025 - Available drivers: Teradata Database ODBC Driver 16.20, 
[*] 192.168.0.2:1025 - Creating connection using ODBC ConnectString: %s
[*] 192.168.0.2:1025 - Setting AUTOCOMMIT to %s
[*] 192.168.0.2:1025 - FETCH_SIZE: 1
[*] 192.168.0.2:1025 - Buffer size for column %s: %s
[*] 192.168.0.2:1025 - SELECT SESSION returned %s
[*] 192.168.0.2:1025 - Executing query on session %s using SQLExecDirectW: %s
[*] 192.168.0.2:1025 - Committing transaction...
[*] 192.168.0.2:1025 - Created session %s.
[*] 192.168.0.2:1025 - Creating cursor %s for session %s.
[*] 192.168.0.2:1025 - Connection successful. Duration: %.3f seconds. Details: %s
[*] 192.168.0.2:1025 - Closing cursor %s for session %s.
[*] 192.168.0.2:1025 - Closing session %s...
[*] 192.168.0.2:1025 - Session %s closed.
[+] 192.168.0.2:1025 - [1/1] - dbc:dbc - Success
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
