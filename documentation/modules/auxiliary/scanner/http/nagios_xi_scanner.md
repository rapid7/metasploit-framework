## Vulnerable Application

The module detects the version of Nagios XI applications and suggests matching exploit modules based on the version number.

The module takes advantage of the `Msf::Exploit::Remote::HTTP::NagiosXi` mixin in order to
authenticate to the target and obtain the version number, which is only revealed to authenticated users.

When used to target a specific host, the module requires valid credentials for a Nagios XI account.
These can be provided via `USERNAME` and `PASSWORD` options.
Alternatively, it is possible to provide a specific Nagios XI version number via the `VERSION` option.
In that case, the module simply suggests matching exploit modules and does not probe the target(s).

The module currently supports the following exploit modules:
- exploit/linux/http/nagios_xi_plugins_check_ping_authenticated_rce (CVE-2019-15949)
- exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce (CVE-2020-35578)
- exploit/linux/http/nagios_xi_mibs_authenticated_rce (CVE-2020-5791)
- exploit/linux/http/nagios_xi_snmptrap_authenticated_rce (CVE-2020-5792)

### Setting up Nagios XI for testing

Vulnerable Nagios XI versions are available [here](https://assets.nagios.com/downloads/nagiosxi/versions.php).
Detailed installation instructions are available
[here](https://assets.nagios.com/downloads/nagiosxi/docs/Installing-Nagios-XI-Manually-on-Linux.pdf)
and an official video tutorial is available [here](https://www.youtube.com/watch?v=fBWA6t6dJ4I).

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/scanner/http/nagios_xi_scanner`
3. Do: `set RHOSTS [IP]`
4. Do: `set USERNAME [username for a valid Nagios XI account]`
5. Do: `set PASSWORD [password for a valid Nagios XI account]`
6. Do: `run`

## Options
### PASSWORD
The password for the Nagios XI account to authenticate with.
### TARGETURI
The base path to Nagios XI. The default value is `/nagiosxi/`.
### USERNAME
The username for the Nagios XI account to authenticate with. The default value is `nagiosadmin`.
### VERSION
The Nagios XI version to check against existing exploit modules. If this option is selected,
the module will not probe the target, so it is not necessary to provide credentials.

## Scenarios
### Nagios XI 5.7.3 running on CentOS 7
```
msf6 auxiliary(scanner/http/nagios_xi_scanner) > show options 

Module options (auxiliary/scanner/http/nagios_xi_scanner):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   nagiosadmin      no        Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.1.14     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /nagiosxi/       yes       The base path to the NagiosXi application
   THREADS    1                yes       The number of concurrent threads (max one per host)
   USERNAME   nagiosadmin      no        Username to authenticate with
   VERSION                     no        Nagios XI version to check against existing exploit modules
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/nagios_xi_scanner) > run

[+] Successfully authenticated to Nagios XI
[*] Target is Nagios XI with version 5.7.3
[+] The target appears to be vulnerable to the following 3 exploit(s):
[*] 
[*]     CVE-2020-35578  exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce
[*]     CVE-2020-5791   exploit/linux/http/nagios_xi_mibs_authenticated_rce
[*]     CVE-2020-5792   exploit/linux/http/nagios_xi_snmptrap_authenticated_rce
[*] 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Nagios XI 5.7.9 version provided via VERSION
```
msf6 auxiliary(scanner/http/nagios_xi_scanner) > show options 

Module options (auxiliary/scanner/http/nagios_xi_scanner):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    no        Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.91.140   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /nagiosxi/       yes       The base path to the NagiosXi application
   THREADS    1                yes       The number of concurrent threads (max one per host)
   USERNAME   nagiosadmin      no        Username to authenticate with
   VERSION    5.7.9            no        Nagios XI version to check against existing exploit modules
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/nagios_xi_scanner) > run

[+] Version 5.7.9 matches the following 1 exploit(s):
[*] 
[*]     CVE-2020-35578  exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce
[*] 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
