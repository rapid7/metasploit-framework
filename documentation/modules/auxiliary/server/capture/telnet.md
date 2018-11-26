This module creates a mock telnet server which accepts credentials.  Upon receiving a login attempt, a `Login failed` error is thrown.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/telnet```
  3. Do: ```run```

## Options

  **BANNER**

  The Banner which should be displayed.  Default is empty, which will display `Welcome`.

  **SSL**

  Boolean if SSL should be used.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

## Scenarios

### Telnet Server and Client

Server:

```
msf5 > use auxiliary/server/capture/telnet 
msf5 auxiliary(server/capture/telnet) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/telnet) > 
[*] Started service listener on 0.0.0.0:23 
[*] Server started.
[+] TELNET LOGIN 127.0.0.1:40016 root / <3@wvu_is_my_hero
```

Client:

```
root@kali:~# telnet 127.0.0.1
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.

Welcome

Login: root
Password: <3@wvu_is_my_hero


Login failed

Connection closed by foreign host.
```
