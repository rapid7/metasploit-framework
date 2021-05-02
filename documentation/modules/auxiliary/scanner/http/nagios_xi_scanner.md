## Vulnerable Application

The module detects the version of Nagios XI running on a target and suggests matching exploit modules based on the version number.

The module takes advantage of the `Msf::Exploit::Remote::HTTP::NagiosXi` mixin in order to
authenticate to the target and obtain the version number, which is only revealed to authenticated users.

When used to target a specific host, the module requires valid credentials for a Nagios XI account.
These can be provided via `USERNAME` and `PASSWORD` options.

Alternatively, it is possible to provide a specific Nagios XI version number via the `VERSION` option.
In that case, the module simply suggests matching exploit modules and does not probe the target(s).

The module is able to recommend the following modules based on the target's Nagios XI version:
- exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce (CVE-2019-15949)
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
### FINISH_INSTALL
If this is set to `true`, the module will try to finish installing Nagios XI on targets where the installation has not been completed.
This includes signing the license agreement. The default value is `false`.
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
### Nagios XI 5.6.5 running on CentOS 7
```
msf6 > use auxiliary/scanner/http/nagios_xi_scanner 
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set rhosts 192.168.1.14
rhosts => 192.168.1.14
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set password nagiosadmin
password => nagiosadmin
msf6 auxiliary(scanner/http/nagios_xi_scanner) > show options 

Module options (auxiliary/scanner/http/nagios_xi_scanner):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FINISH_INSTALL  false            no        If the Nagios XI installation has not been completed, try to do so
                                              . This includes signing the license agreement.
   PASSWORD        nagiosadmin      no        Password to authenticate with
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          192.168.1.14     yes       The target host(s), range CIDR identifier, or hosts file with synt
                                              ax 'file:<path>'
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /nagiosxi/       yes       The base path to the Nagios XI application
   THREADS         1                yes       The number of concurrent threads (max one per host)
   USERNAME        nagiosadmin      no        Username to authenticate with
   VERSION                          no        Nagios XI version to check against existing exploit modules
   VHOST                            no        HTTP server virtual host

msf6 auxiliary(scanner/http/nagios_xi_scanner) > run

[+] Successfully authenticated to Nagios XI
[*] Target is Nagios XI with version 5.6.5
[+] The target appears to be vulnerable to the following 4 exploit(s):
[*] 
[*]     CVE-2019-15949  exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce.rb
[*]     CVE-2020-35578  exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce
[*]     CVE-2020-5792   exploit/linux/http/nagios_xi_snmptrap_authenticated_rce
[*]     CVE-2020-5791   exploit/linux/http/nagios_xi_mibs_authenticated_rce
[*] 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
### Nagios XI 5.7.9 version provided via VERSION
```
msf6 > use auxiliary/scanner/http/nagios_xi_scanner 
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set rhosts 192.168.1.14
rhosts => 192.168.1.14
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set version 5.7.9
version => 5.7.9
msf6 auxiliary(scanner/http/nagios_xi_scanner) > show options 

Module options (auxiliary/scanner/http/nagios_xi_scanner):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FINISH_INSTALL  false            no        If the Nagios XI installation has not been completed, try to do so
                                              . This includes signing the license agreement.
   PASSWORD                         no        Password to authenticate with
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          192.168.1.14     yes       The target host(s), range CIDR identifier, or hosts file with synt
                                              ax 'file:<path>'
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /nagiosxi/       yes       The base path to the Nagios XI application
   THREADS         1                yes       The number of concurrent threads (max one per host)
   USERNAME        nagiosadmin      no        Username to authenticate with
   VERSION         5.7.9            no        Nagios XI version to check against existing exploit modules
   VHOST                            no        HTTP server virtual host

msf6 auxiliary(scanner/http/nagios_xi_scanner) > run

[+] Version 5.7.9 matches the following 1 exploit(s):
[*] 
[*]     CVE-2020-35578  exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce
[*] 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Nagios XI 5.7.5 - incomplete installation, FINISH_INSTALL set to true
```
msf6 > use auxiliary/scanner/http/nagios_xi_scanner 
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set rhosts 192.168.1.16
rhosts => 192.168.1.16
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set password nagiosadmin
password => nagiosadmin
msf6 auxiliary(scanner/http/nagios_xi_scanner) > set finish_install true
finish_install => true
msf6 auxiliary(scanner/http/nagios_xi_scanner) > show options 

Module options (auxiliary/scanner/http/nagios_xi_scanner):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FINISH_INSTALL  true             no        If the Nagios XI installation has not been completed, try to do so
                                              . This includes signing the license agreement.
   PASSWORD        nagiosadmin      no        Password to authenticate with
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          192.168.1.16     yes       The target host(s), range CIDR identifier, or hosts file with synt
                                              ax 'file:<path>'
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /nagiosxi/       yes       The base path to the Nagios XI application
   THREADS         1                yes       The number of concurrent threads (max one per host)
   USERNAME        nagiosadmin      no        Username to authenticate with
   VERSION                          no        Nagios XI version to check against existing exploit modules
   VHOST                            no        HTTP server virtual host

msf6 auxiliary(scanner/http/nagios_xi_scanner) > run 
[*] Attempting to authenticate to Nagios XI...   
[!] The target seems to be a Nagios XI application that has not been fully installed yet.
[*] Attempting to finish the Nagios XI installation on the target using the provided password. The username will be `nagiosadmin`.
[*] Attempting to authenticate to Nagios XI...
[!] The Nagios XI license agreement has not yet been signed on the target.
[*] Attempting to sign the Nagios XI license agreement... 
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI
[*] Target is Nagios XI with version 5.7.5
[+] The target appears to be vulnerable to the following 1 exploit(s):
[*] 
[*]     CVE-2020-35578  exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce
[*] 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
