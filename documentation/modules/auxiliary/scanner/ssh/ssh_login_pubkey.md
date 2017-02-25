## SSH Service

  SSH, Secure SHell, is an encrypted network protocol used to remotely interact with an Operating System at a command line level.  SSH is available on most every system, including Windows, but is mainly used by *nix administrators.
  This module attempts to login to SSH with username and private key combinations.  For username and password logins, please use `auxiliary/scanner/ssh/ssh_login`.
  It should be noted that some modern Operating Systems have default configurations to not allow the `root` user to remotely login via SSH, or to only allow `root` to login with an SSH key login.

### Key Generation

  On most modern *nix Operating System, the `ssh-keygen` command can be utilized to create an SSH key.  Metasploit expects the key to be unencrypted, so no password should be set during `ssh-keygen`.
  After following the prompts to create the SSH key pair, the `pub` key needs to be added to the authorized_keys list.  To do so simply run: `cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys`

## Verification Steps

  1. Install SSH and start it.
  2. Create an SSH keypair and add the public key to the `authorized_keys` file
  3. Start msfconsole
  4. Do: ` use auxiliary/scanner/ssh/ssh_login_pubkey`
  5. Do: `set rhosts`
  6. Do: set usernames with one of the available options
  7. Do: `set KEY_PATH ` to either a file or path
  7. Do: `run`
  8. You will hopefully see something similar to the following:

  ```
  [+] SSH - Success: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
  ```

## Options

  **KEY_PATH**

  A string to the private key to attempt, or a folder containing private keys to attempt.  Any file name starting with a period (`.`) or ending in `.pub` will be ignored.
  An SSH key is typically kept in a user's home directory under `.ssh/id_rsa`.  The file contents, when not encrypted with a password will start with `-----BEGIN RSA PRIVATE KEY-----`
  
  **RHOSTS**
  
  Either a comma space (`, `) separated list of hosts, or a file containing list of hosts, one per line.  File Example: `file://root/ssh_hosts.lst`, list example: `192.168.0.1` or `192.168.0.1, 192.168.0.2`

  **STOP_ON_SUCCESS**
  
  If a valid login is found on a host, immediately stop attempting additional logins on that host.

  **USERNAME**
  
  Username to try for each password.
  
  **USER_FILE**
  
  A file containing a username on every line.

  **VERBOSE**
  
  Show a failed login attempt.  This can get rather verbose when large `USER_FILE`s or `KEY_PATH`s are used.  A failed attempt will look similar to the following: `[-] SSH - Failed`

## Option Combinations

It is important to note that usernames can be entered in multiple combinations.  For instance, a username could be set in `USERNAME`, and be part of `USER_FILE`.
This module makes a combination of all of the above when attempting logins.  So if a username is set in `USERNAME`, and a `USER_FILE` is listed, usernames will be generated from BOTH of these.

## Scenarios

  Example run with a FOLDER set for `KEY_PATH` against:
  * Ubuntu 14.04 Server

  While the two SSH key are nearly identical, one character has been modified in one of the keys to prevent a successful login.

```
msf > use auxiliary/scanner/ssh/ssh_login_pubkey 
msf auxiliary(ssh_login_pubkey) > set rhosts 192.168.2.156
rhosts => 192.168.2.156
msf auxiliary(ssh_login_pubkey) > set username ubuntu
username => ubuntu
msf auxiliary(ssh_login_pubkey) > set key_path /root/sshkeys/
key_path => /root/sshkeys/
msf auxiliary(ssh_login_pubkey) > run

[*] 192.168.2.156:22 SSH - Testing Cleartext Keys
[*] SSH - Testing 2 keys from /root/sshkeys
[-] SSH - Failed: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
aAz8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----

'
[!] No active DB -- Credential data will not be saved!
[+] SSH - Success: 'ubuntu:-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwJrqowPyjWONHUCMqU/Fh3yRn42+X9hahtTv/6plYpb4WrA
NxDaYIrBGAO//u2SkGcIhnAdzYVmovWahKEwcxZ2XJo/nj4gjh1CbI1xVCFeE/oX
oWpIN+4q8JQ0Iq1dm+c+WPQIEzlVpMRaKeuMxdGPNMTYWxolSEIMPPYmyWXG6gz8
fYYZDo8+w8G78w7oUV6hSIwCDzw09A5yGyt51ZETeSZiZ24bHlBQSyk7yFq/eo58
xhlc79jpZrSdX8kx8HrCZKND7O6E4YSktfSHOvd81QUCSyoi5Y+9RXsLjUEba0+Y
0Az8mZPLdxbRu75eeD/mZTv5gALewXeb65IkPQIDAQABAoIBACvi5LbNR6wSE7v4
o0JJ5ksDe2n0MnK6XT34t6i/BSPbPhVcaCPMYtHr9Eox/ATCK/d8/cpfcIYsi2Rg
yWEs1lWC+XdTdhYYh+4MjjVB5f9q0QixXKFUv2TKNHnk0GvQbzZHyefC/Xy+rw8I
FyceWW/GxTS+T7PpHS+qxwyHat24ph7Xz/cE/0UyrVu+NAzFXaHq60M2/RRh3uXE
1vqiZVlapczO/DxsnPwQrE2EOm0lzrQVmZbX5BYK1yiCd5eTgLhOb+ms2p/8pb2I
jrK5FzLnUZu0H0ZHtihOVkx4l8NZqB36jinaRs0wWN7It4/C5+NkyoMvuceIn1Wx
tstYD3ECgYEA7sOb0CdGxXw0IVrJF+3C8m1UG3CfQfzms+rJb9w3OJVl2BTlYdPr
JgXI/YoV9FQPvXmTWrRP9e6x0kuSVHO1ejMpyLHGmMcJDZhpVKMROOosIWfROxwk
bkPU2jdUXIrHgu8NnmnyytjUnJgeerQZLhCtjKmBKCZisS4WPBdun3MCgYEAxDh1
fjFJttWhgeg6pcvvmDUWO1W0lJ9ZjjQll1UmbPmKDGwwsjPZEkZfLkvI77st81AT
eW/p7tMKE3fCkXkn2KWMQ6ZGN5yflwvjJOMAVZz8ir8Cu1npa6f6HIrxpHSKethY
dG4ssCpQctfoRfN4wg6fOHBOpGd3BH1GdOwR4Y8CgYEAq3h7e//ZCZbrcVDbvn2Y
VbZCgvpcxW002d0yEU2bst1IKOjI23rwE3xwHfV/UtrT+wVG2AtKqZpkxlxTmKcI
m9wGlAVoVOwMCmF8s7XwdmlmjA8c6lCJsU6xnI3D3jokklnP9AauwRL7jgKJUSHq
O3TqzmwlP4phslEg0sMZRRUCgYEAwkS3prG7rqYBmjFG52FqnIJquWIYQFEoBE+C
rDqkqZ3B3Jy89aG5l4tOrvJfRWJHky7DqSZxMH+G6VFXtFmEZs04er3DpUmPA6fE
Qn/wk9KygdetJ7pUDL8pNFsn9M9hT1Ck+tkdq2ipb5ptn9v2wgJiBynB4qmBP1Oc
jyQua+cCgYEAl77hJQK97tdJ5TuOXSsdpW8IMvbiaWTgvZtKVJev31lWgJ+knpCf
AaZna5YokhaNvfGGbO5N8YoYShIpGdvWI+dIT8xYvPkJmYdnTz7/dmBUcwLtNVx/
7PI/l5XrFMRsnu/CYuBPuWB+RCTLjIr1D1RluNbIb7xr+kDHuzgInvA=
-----END RSA PRIVATE KEY-----

' 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare) Linux Ubuntu14 4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.168.2.117:44179 -> 192.168.2.156:22) at 2017-02-22 22:08:11 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
