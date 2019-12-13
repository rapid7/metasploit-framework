
## Vulnerable Application

  This Module lists current TCP sessions.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/tcpnetstat`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

  ```
  SESSION
  ```
  The session to run the module on.

## Scenarios

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49184) at 201 9-12-12 14:55:42 -0700

  msf5 exploit(multi/handler) > use post/windows/gather/tcpnetstat
  msf5 post(windows/gather/tcpnetstat) > set SESSION 1
    SESSION => 1
  msf5 post(windows/gather/tcpnetstat) > run

    [*] TCP Table Size: 412
    [*] Total TCP Entries: 10
    [*] Connection Table
    ================

    STATE        LHOST         LPORT  RHOST        RPORT
    -----        -----         -----  -----        -----
    ESTABLISHED  192.168.1.10  49184  192.168.1.3  4444
    LISTEN       0.0.0.0       135    0.0.0.0      _
    LISTEN       0.0.0.0       445    0.0.0.0      _
    LISTEN       0.0.0.0       5357   0.0.0.0      _
    LISTEN       0.0.0.0       49152  0.0.0.0      _
    LISTEN       0.0.0.0       49153  0.0.0.0      _
    LISTEN       0.0.0.0       49154  0.0.0.0      _
    LISTEN       0.0.0.0       49155  0.0.0.0      _
    LISTEN       0.0.0.0       49156  0.0.0.0      _
    LISTEN       192.168.1.10  139    0.0.0.0      _

    [*] Post module execution completed
  ```
