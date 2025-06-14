## Vulnerable Application

This module can determine what public keys are configured for key-based authentication across a range of machines,
users, and sets of known keys. The SSH protocol indicates whether a particular key is accepted prior to the client
performing the actual signed authentication request. To use this module, a text file containing one or more SSH keys
should be provided. These can be private or public, so long as no passphrase is set on the private keys.

If you have loaded a database plugin and connected to a database, this module will record authorized public keys and
hosts so you can track your process. Key files may be a single public (unencrypted) key, or several public keys
concatenated together as an ASCII text file. Non-key data should be silently ignored. Private keys will only utilize
the public key component stored within the key file.

### Setup

This module has been tested against Metasploitable2. Installation and setup instructions and additional
information can be found in the Rapid7 documentation here: https://docs.rapid7.com/metasploit/metasploitable-2/

## Verification Steps

1. Have Metasploitable2 running
1. Copy the `msfadmin`'s public key from `/home/msfadmin/.ssh/id_rsa.pub` to your machine
1. Start `msfconsole -q`
1. Do: `use auxiliary/scanner/ssh/ssh_identify_pubkeys`
1. Do: `set rhosts`
1. Do: `set username root`
1. Do: `set key_path` to the copied `id_rsa.pub` file
1. Do: `run`

## Options

### KEY_FILE

Filename of one or several cleartext public keys.

### SSH_DEBUG

When enabled, outputs verbose SSH debug messages.

### SSH_BYPASS

When enabled, verify that authentication was not bypassed when keys are found.

### SSH_KEYFILE_B64

Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.

### KEY_DIR

Directory of several keys. Filenames must not begin with a dot in order to be read.

### SSH_TIMEOUT

The maximum time to negotiate a SSH session.

## Scenarios

### Metasploitable22

```shell
msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > cat id_rsa.pub
[*] exec: cat id_rsa.pub

ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable

msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > options

Module options (auxiliary/scanner/ssh/ssh_identify_pubkeys):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   KEY_FILE          id_rsa.pub       yes       Filename of one or several cleartext public keys.
   RHOSTS            192.168.112.178  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME          root             no        A specific username to authenticate as
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssh/ssh_identify_pubkeys) > run

[*] 192.168.112.178:22 SSH - Trying 1 cleartext key per user.
[+] 192.168.112.178:22 - [1/1] - Public key accepted: 'root' with key '57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a' (Private Key: No) - msfadmin@metasploitable
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
