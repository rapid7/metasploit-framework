## Vulnerable Application

Web sites & other HTTP based applications may be vulnerable to directory brute forcing. This module executes a directory
brute force on a web server, in order to discover locations on the web server for further analysis. This is not the same
as using a word dictionary - this module uses string permutations instead.

### Install

Any web server that serves directories can be used. This module can support different authentication methods, which will
depend on the type of web server used.

## Verification Steps

1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/brute_dirs`
1. Do: `set rhosts [IPs]`
1. Do: `run`
1. As the module executes you should see a list of directories that are being served up by the web server.

## Options

### DELAY

The delay between connections, per thread, in milliseconds. Using this will reduce the speed of the
module, which may be useful to prevent any rate limiting or web application firewalls from preventing further scanning.
Defaults to `0`.

### FORMAT

The comma separated list of expected directory formats used to determine the order of brute
force attempts.
Defaults to `a,aa,aaa`.

Use the following format specifiers:

|Format specifier|Character type|
|---|---|
|a  | lowercase alpha|
|d  | digit|
|A  | uppercase alpha|

The default value will search `a,aa,aaa` will search for 1 character directories, then 2 character directories, then 3
character directories.

### JITTER

The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds. Using jitter ensures
requests have a random amount of additional delay. This is also useful for evading brute force prevention.
Defaults to `0`.

### PATH

The path to starting identification of directories from.
Defaults to `/`.

### THREADS

The number of concurrent threads (max one per host).
Defaults to `1`.

### TIMEOUT

The socket connect/read timeout in seconds.
Defaults to `20`.

### ErrorCode

The expected HTTP code for non existent directories.
Defaults to `404`.

### HTTP404Sigs

Path of 404 signatures to use to identify 'file not found' strings
in website output, even if a successful HTTP Status Code is returned by the server.
Defaults to `[Metasploit data directory]/wmap/wmap_404s.txt`.

## Scenarios

### HTTP directory brute force on a specific port

Identify an open HTTP port on a target web server by using `nmap`:

```
nmap -p8080 192.168.2.3
.
.
.
PORT     STATE SERVICE
8080/tcp   open  http

```

Configure the `brute_dirs` module to use the identified IP address and port number:

```
msf5 > use auxiliary/scanner/http/brute_dirs 
msf5 auxiliary(scanner/http/brute_dirs) > set RHOSTS 192.168.2.3
msf5 auxiliary(scanner/http/brute_dirs) > set RPORT 8080
RHOSTS => 192.168.2.3
msf5 auxiliary(scanner/http/brute_dirs) > run

[*] Using code '404' as not found.
[+] Found http://192.168.2.3:8080/dav/ 200
[+] Found http://192.168.2.3:8080/img/ 200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Testing against multiple hosts using a CIDR

```
msf5 > use auxiliary/scanner/http/brute_dirs
msf5 auxiliary(scanner/http/brute_dirs) > show options
    ... show and set options ...
msf5 auxiliary(scanner/http/brute_dirs) > set RHOSTS 192.168.2.1/24
msf5 auxiliary(scanner/http/brute_dirs) > run
```

### Custom format to find specifically formatted directories

A format string of `Aaaaad` will search for 6 character directories, starting with a capital letter and ending in a
digit. E.g.

```
msf5 > use auxiliary/scanner/http/brute_dirs 
msf5 auxiliary(scanner/http/brute_dirs) > set RHOSTS 192.168.2.3
msf5 auxiliary(scanner/http/brute_dirs) > set FORMAT 'Aaaaad'
msf5 auxiliary(scanner/http/brute_dirs) > run
```
