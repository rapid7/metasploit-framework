## Description

Nuuo CMS Session Bruteforce

The NUUO CMS protocol uses session tokens in a similar way to HTTP cookies. As mentioned in the summary, if a USERLOGIN request is sent with a correct username and password, a "User-Session-No" token will be returned. The number returned is composed of 8 digits, so if an attacker wanted to guess it, they would have 10 million possibilities, and would be able to bruteforce it on average after 5 million tries.

The function responsible for creating a new user is at offset 0x454E80 in CMS_Server.exe version 2.1. It sets up a new user object and returns the session token to the calling function. This function has what is probably a coding error - the number returned is actually not a number, but the heap address of the user object created by invoking "new()" in the user object class. An assembly snippet is shown below:

```
.text:00454E80 000                 push    0FFFFFFFFh
.text:00454E82 004                 push    offset loc_5E2013
.text:00454E87 008                 mov     eax, large fs:0
.text:00454E8D 008                 push    eax
.text:00454E8E 00C                 sub     esp, 8    
.text:00454E91 014                 push    ebp
.text:00454E92 018                 push    esi
.text:00454E93 01C                 push    edi
.text:00454E94 020                 mov     eax, dword_68D134
.text:00454E99 020                 xor     eax, esp   
.text:00454E9B 020                 push    eax
.text:00454E9C 024                 lea     eax, [esp+24h+var_C]
.text:00454EA0 024                 mov     large fs:0, eax
.text:00454EA6 024                 mov     ebp, ecx
.text:00454EA8 024                 lea     edi, [ebp+43Ch] 
.text:00454EAE 024                 push    edi             ; lpCriticalSection_EnterCriticalSection
.text:00454EAF 028                 mov     [esp+28h+var_10], edi
.text:00454EB3 028                 call    ds:EnterCriticalSection
.text:00454EB9 024                 push    1B8h            ; unsigned int
.text:00454EBE 028                 mov     [esp+28h+var_4], 0
.text:00454EC6 028                 call    ??2@YAPAXI@Z    ; new() operator, returns object in eax
(...)
```

After the call to ??2@YAPAXI@Z in .text:00454EC6, the session number is returned to the calling function (sub_457100), which then stores it and sends it back to the client as the valid session number:

```
NUCM/1.0 200 OK
User-Valid: %d
Server-Version: %s
Ini-Version: %d
License-Number: %d
User-Session-No: %u <---- session number, which is a hexadecimal memory address converted to decimal
```

These session numbers (tokens) are not that easy to predict, however after collecting thousands of samples I was able to build a table of the most common occurrences, which reduces the possibilities from 10 million to about 1.2 million. In practice, the tokens can usually be guessed between in less than 500,000 attempts - an improvement of 95% over standard bruteforcing. It is likely this can be further improved with some deeper analysis, but due to time constraints this was not investigated further. The tables used to do the bruteforcing are in Appendix #C.

This attack is perfectly feasible despite the high number of attempts needed. Firstly, there is no bruteforce protection on the CMS server, so we can just flood it with requests and find the session number in less than an hour. 
Secondly, due to the nature of this application, it is normal to have the software clients logged in for a long amount of time (days, weeks) in order to monitor the video cameras controlled by CMS.

It is worth noticing that when a user logs in, the session has to be maintained by periodically sending a PING request. To bruteforce the session, we send each guess with a PING request until a 200 OK message is received. 

## Vulnerable Application

[NUUO Central Management Server (CMS): all versions below 2.4.0](d1.nuuo.com/NUUO/CMS/)

 - 1.5.2 OK
 - 2.1.0 OK
 - 2.3.0 OK

## Scenarios

### Tested on Windows 10 Pro x64 running NCS Server v2.1.0

```
msf5 auxiliary(gather/nuuo_cms_bruteforce) > set rhosts 172.22.222.200
rhosts => 172.22.222.200
msf5 auxiliary(gather/nuuo_cms_bruteforce) > exploit

[*] 172.22.222.200:5180 - Bruteforcing session - this might take a while, go get some coffee!
[*] 172.22.222.200:5180 - Generating 2621440 session tokens
[+] 172.22.222.200:5180 - Found valid user session: 42094216
[*] 172.22.222.200:5180 - Time taken: 1384.588721601991 seconds; total tries 590893
[*] Auxiliary module execution completed
msf5 auxiliary(gather/nuuo_cms_bruteforce) >
```

## References

https://ics-cert.us-cert.gov/advisories/ICSA-18-284-02

https://raw.githubusercontent.com/pedrib/PoC/master/advisories/nuuo-cms-ownage.txt
