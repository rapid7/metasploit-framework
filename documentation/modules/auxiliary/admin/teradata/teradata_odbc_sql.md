The teradata_odbc_sql module is used to run SQL queries for Teradata databases.

## Vulnerable Application

* Teradata Database
* Teradata Express

Teradata databases can be identified by scanning for TCP port 1025. An Nmap version scan can confirm if the service is recognized as Teradata.

The teradata_odbc_login module can be used to brute-force credentials.

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
4. Do: `use auxiliary/admin/teradata/teradata_odbc_sql`
5. Do: `set RHOSTS [IPs]`
6. Do: `set USERNAME [username to try]`
7. Do: `set PASSWORD [password to try]`
   * The default Teradata credentials are the matching username and password 'DBC'.
8. Set a SQL query for the 'SQL' option.
   * The default is `SELECT DATABASENAME FROM DBC.DATABASES`
9. Do: `run`

```
msf > use auxiliary/admin/teradata/teradata_odbc_sql 
msf auxiliary(admin/teradata/teradata_odbc_sql) > show options

Module options (auxiliary/admin/teradata/teradata_odbc_sql):

   Name      Current Setting                         Required  Description
   ----      ---------------                         --------  -----------
   PASSWORD  dbc                                     yes       Password
   RHOSTS                                            yes       The target address range or CIDR identifier
   SQL       SELECT DATABASENAME FROM DBC.DATABASES  yes       SQL query to perform
   THREADS   1                                       yes       The number of concurrent threads
   USERNAME  dbc                                     yes       Username

msf auxiliary(admin/teradata/teradata_odbc_sql) > set RHOSTS 192.168.0.2
RHOSTS => 192.168.0.2
msf auxiliary(admin/teradata/teradata_odbc_sql) > run

[*] Running for 192.168.0.2...
[*] 192.168.0.2 - dbc:dbc - Starting
[*] 192.168.0.2 - Creating connection: %s
[*] 192.168.0.2 - Loading ODBC Library: %s
[*] 192.168.0.2 - Available drivers: Teradata Database ODBC Driver 16.20, 
[*] 192.168.0.2 - Connection successful. Duration: %.3f seconds. Details: %s
[+] 192.168.0.2 - dbc:dbc - Login Successful
[*] 192.168.0.2 - Starting - SELECT DATABASENAME FROM DBC.DATABASES
[*] 192.168.0.2 - Query Successful. Duration: %.3f seconds,%sQuery: %s%s
[+] 192.168.0.2 - Row 1: [DatabaseUser                  ]
[+] 192.168.0.2 - Row 2: [All                           ]
[+] 192.168.0.2 - Row 3: [SYSJDBC                       ]
[+] 192.168.0.2 - Row 4: [TDStats                       ]
[+] 192.168.0.2 - Row 5: [TD_SYSXML                     ]
[+] 192.168.0.2 - Row 6: [PUBLIC                        ]
[+] 192.168.0.2 - Row 7: [DBC                           ]
[+] 192.168.0.2 - Row 8: [SYSBAR                        ]
[+] 192.168.0.2 - Row 9: [TD_SYSGPL                     ]
[+] 192.168.0.2 - Row 10: [SYSLIB                        ]
[+] 192.168.0.2 - Row 11: [SQLJ                          ]
[+] 192.168.0.2 - Row 12: [LockLogShredder               ]
[+] 192.168.0.2 - Row 13: [Default                       ]
[+] 192.168.0.2 - Row 14: [TDPUSER                       ]
[+] 192.168.0.2 - Row 15: [TD_SYSFNLIB                   ]
[+] 192.168.0.2 - Row 16: [EXTUSER                       ]
[+] 192.168.0.2 - Row 17: [tdwm                          ]
[+] 192.168.0.2 - Row 18: [SystemFe                      ]
[+] 192.168.0.2 - Row 19: [External_AP                   ]
[+] 192.168.0.2 - Row 20: [TDQCD                         ]
[+] 192.168.0.2 - Row 21: [dbcmngr                       ]
[+] 192.168.0.2 - Row 22: [Sys_Calendar                  ]
[+] 192.168.0.2 - Row 23: [SysAdmin                      ]
[+] 192.168.0.2 - Row 24: [TD_SERVER_DB                  ]
[+] 192.168.0.2 - Row 25: [TDMaps                        ]
[+] 192.168.0.2 - Row 26: [SYSUDTLIB                     ]
[+] 192.168.0.2 - Row 27: [Crashdumps                    ]
[+] 192.168.0.2 - Row 28: [SYSSPATIAL                    ]
[+] 192.168.0.2 - Row 29: [MyUser                        ]
[+] 192.168.0.2 - Row 30: [SYSUIF                        ]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
