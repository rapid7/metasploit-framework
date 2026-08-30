## Vulnerable Application

This module checks for accessible WordPress pingback functionality.

Pingback is an XML-RPC feature in WordPress that allows blogs to notify each other of references.
If enabled, it can be abused for:

- DDoS amplification attacks
- Internal network scanning
- Information disclosure

To test this module:

1. Set up a WordPress instance (any version with XML-RPC enabled)
2. Ensure `/xmlrpc.php` is accessible
3. Pingback functionality should not be disabled

## Verification Steps

1. Start Metasploit: `msfconsole`
2. Load the module: `use auxiliary/scanner/http/wordpress_pingback_access`
3. Set the target: `set RHOSTS example.com`
4. Run the module: `run`

If vulnerable, the module will indicate that pingback access is enabled.

## Options

This module has no additional options beyond the standard ones.

## Scenarios

Example usage against a WordPress site with pingback enabled:
```bash
msf > use auxiliary/scanner/http/wordpress_pingback_access
msf auxiliary(scanner/http/wordpress_pingback_access) > set RHOSTS example.com
RHOSTS => example.com
msf auxiliary(scanner/http/wordpress_pingback_access) > run
[*] Checking pingback access on example.com
[+] Pingback is enabled and accessible at /xmlrpc.php
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/wordpress_pingback_access) >
```
