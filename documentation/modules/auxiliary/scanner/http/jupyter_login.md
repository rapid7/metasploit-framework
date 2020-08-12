## Vulnerable Application

This module checks if authentication is required on a Jupyter Lab or Notebook server. If it is, this module will
bruteforce the password. Jupyter only requires a password to authenticate, usernames are not used. This module is
compatible with versions 4.3.0 (released 2016-12-08) and newer. [Version 4.3.0][1] is the first version in which
authentication is required by default.

A note on names, "Jupyter Lab" is the next-generation interface for "Jupyter Notebooks" which was the successor of the
original IPython Notebook system. This module is compatible with both standard Jupyter Notebook and Jupyter Lab servers.

### Installation

1. Install the latest version of Jupyter from PyPi using pip: `pip install notebook`. The "notebook" package is the core
  application and is the one whose version number is used as the Jupyter version number referred to in this document.
1. Start Jupyter using `jupyter notebook --ip='*'` to start Jupyter listening on all IP addresses.
    * New installs will randomly generate an authentication token and open the browser with it
    * As of [version 5.3][2], the user will be prompted to set a password the first time they open the UI
    * Note that you may need to restart Jupyter after changing the password in order for Jupyter to start using the new password.
    * If you can't reset the password, it may be because you need to create the directory `.jupyter` in the directory 
    you are running the `jupyter notebook --ip='*'` command from.
1. With the password set, the module can be tested

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/jupyter_login`
1. Set the `RHOSTS` option
    * With no other options set, this will only check if authentication is required
1. Do: `run`
1. You should the server version
1. If password options (such as `PASS_FILE`) where specified, and the server requires authentication then you should see
   login attempts

## Options

## Scenarios

### Jupyter Notebook 4.3.0 With No Authentication Requirement

```
msf5 > use auxiliary/scanner/http/jupyter_login 
msf5 auxiliary(scanner/http/jupyter_login) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf5 auxiliary(scanner/http/jupyter_login) > set PASS_FILE /tmp/passwords.txt
PASS_FILE => /tmp/passwords.txt
msf5 auxiliary(scanner/http/jupyter_login) > run

[*] 192.168.159.128:8888 - The server responded that it is running Jupyter version: 4.3.0
[+] 192.168.159.128:8888 - No password is required.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/jupyter_login) >
```

### Jupyter Notebook 6.0.2 With A Password Set

```
msf5 > use auxiliary/scanner/http/jupyter_login 
msf5 auxiliary(scanner/http/jupyter_login) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf5 auxiliary(scanner/http/jupyter_login) > set PASS_FILE /tmp/passwords.txt
PASS_FILE => /tmp/passwords.txt
msf5 auxiliary(scanner/http/jupyter_login) > run

[*] 192.168.159.128:8888 - The server responded that it is running Jupyter version: 6.0.2
[-] 192.168.159.128:8888 - LOGIN FAILED: :Password (Incorrect)
[+] 192.168.159.128:8888 - Login Successful: :Password1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/jupyter_login) >
```

[1]: https://jupyter-notebook.readthedocs.io/en/stable/changelog.html#release-4-3
[2]: https://jupyter-notebook.readthedocs.io/en/stable/public_server.html#automatic-password-setup
