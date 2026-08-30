Metasploit plugins can change the behavior of Metasploit framework by adding new features, new user interface commands, and more.
They are designed to have a very loose definition in order to make them as useful as possible.

Plugins are not available by default, they need to be loaded:

```msf
msf > load plugin_name
```

Plugins can be automatically loaded and configured on msfconsole's start up by configuring a custom `~/.msf4/msfconsole.rc` file:

```msf
load plugin_name
plugin_name_command --option
```

## Available Plugins

The current available plugins for Metasploit can be found by running the `load -l` command, or viewing Metasploit's [plugins](https://github.com/rapid7/metasploit-framework/tree/master/plugins) directory:

| Name             | Description                                                                                         |
|------------------|-----------------------------------------------------------------------------------------------------|
| aggregator       | Interacts with the external Session Aggregator                                                      |
| alias            | Adds the ability to alias console commands                                                          |
| auto_add_route   | Adds routes for any new subnets whenever a session opens                                            |
| beholder         | Capture screenshots, webcam pictures, and keystrokes from active sessions                           |
| besecure         | Integrates with the beSECURE - open source vulnerability management                                 |
| capture          | Start all credential capture and spoofing services                                                  |
| db_credcollect   | Automatically grab hashes and tokens from Meterpreter session events and store them in the database |
| db_tracker       | Monitors socket calls and updates the database backend                                              |
| event_tester     | Internal test tool used to verify the internal framework event subscriber logic works               |
| ffautoregen      | This plugin reloads and re-executes a file-format exploit module once it has changed                |
| fzuse            | A plugin offering a fuzzy use command                                                               |
| ips_filter       | Scans all outgoing data to see if it matches a known IPS signature                                  |
| lab              | Adds the ability to manage VMs                                                                      |
| libnotify        | Send desktop notification with libnotify on sessions and db events                                  |
| msfd             | Provides a console interface to users over a listening TCP port                                     |
| msgrpc           | Provides a MessagePack interface over HTTP                                                          |
| nessus           | Nessus Bridge for Metasploit                                                                        |
| nexpose          | Integrates with the Rapid7 Nexpose vulnerability management product                                 |
| openvas          | Integrates with the OpenVAS - open source vulnerability management                                  |
| payloads_manager | Manages payloads for exploitation                                                                   |
| pcap_log         | Logs all socket operations to pcaps (in /tmp by default)                                            |
| request          | Make requests from within Metasploit using various protocols.                                       |
| rssfeed          | Create an RSS feed of events                                                                        |
| sample           | Demonstrates using framework plugins                                                                |
| session_notifier | This plugin notifies you of a new session via SMS                                                   |
| session_tagger   | Automatically interacts with new sessions to create a new remote TaggedByUser file                  |
| socket_logger    | Log socket operations to a directory as individual files                                            |
| sounds           | Automatically plays a sound when various framework events occur                                     |
| sqlmap           | sqlmap plugin for Metasploit                                                                        |
| thread           | Internal test tool for testing thread usage in Metasploit                                           |
| token_adduser    | Attempt to add an account using all connected Meterpreter session tokens                            |
| token_hunter     | Search all active Meterpreter sessions for specific tokens                                          |
| wiki             | Outputs stored database values from the current workspace into DokuWiki or MediaWiki format         |
| wmap             | Web assessment plugin                                                                               |

## Examples

### Alias Plugin

The Alias plugin adds the ability to alias console commands:

```msf
msf > load alias
[*] Successfully loaded plugin: alias
msf > alias -h
Usage: alias [options] [name [value]]

OPTIONS:

    -c   Clear an alias (* to clear all).
    -f   Force an alias assignment.
    -h   Help banner.
```

Register an alias such as `proxy_enable`:

```msf
msf > alias proxy_enable "set Proxies http:localhost:8079"
```

Now when running the aliased `proxy_enable` command, the proxy datastore value will be set for the current module:

```msf
msf auxiliary(scanner/http/title) > proxy_enable
Proxies => http:localhost:8079
```

Viewing registered aliases:

```msf
msf > alias

Current Aliases
===============

       Alias Name    Alias Value
       ----------    -----------
alias  proxy_enable  set Proxies http:localhost:8079

```

To automatically load and configure the alias plugin on startup of Metasploit, create a custom `~/.msf4/msfconsole.rc` file:

```msf
load alias
alias proxy_enable "set Proxies http:localhost:8079"
alias proxy_disable "unset Proxies"
alias routes "route print"
```

### Capture Plugin

Capturing credentials is a critical and early phase in the playbook of many offensive security testers. Metasploit has
facilitated this for years with protocol-specific modules all under the `modules/auxiliary/server/capture` directory. Users can start and configure
each of these modules individually, but now the capture plugin can streamline the process. The capture plugin can easily start 13
different services (17 including SSL enabled versions) on the same listening IP address including remote interfaces via Meterpreter.
A configuration file can be used to select individual services to start and once finished, all services can easily be stopped
using a single command.

To use the plugin, it must first be loaded. That will provide the `captureg` command (for Capture-Global) which then offers start
and stop subcommands. In the following example, the plugin is loaded, and then all default services are started on the 192.168.159.128 interface.

```msf
msf > load capture
[*] Successfully loaded plugin: Credential Capture
msf > captureg start --ip 192.168.159.128
Logging results to /home/smcintyre/.msf4/logs/captures/capture_local_20220325104416_589275.txt
Hash results stored in /home/smcintyre/.msf4/loot/captures/capture_local_20220325104416_612808
[+] Authentication Capture: DRDA (DB2, Informix, Derby) started
[+] Authentication Capture: FTP started
[+] HTTP Client MS Credential Catcher started
[+] HTTP Client MS Credential Catcher started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: MSSQL started
[+] Authentication Capture: MySQL started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: PostgreSQL started
[+] Printjob Capture Service started
[+] Authentication Capture: SIP started
[+] Authentication Capture: SMB started
[+] Authentication Capture: SMTP started
[+] Authentication Capture: Telnet started
[+] Authentication Capture: VNC started
[+] Authentication Capture: FTP started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: SMTP started
[+] NetBIOS Name Service Spoofer started
[+] LLMNR Spoofer started
[+] mDNS Spoofer started
[+] Started capture jobs
msf >
```

This content was originally posted on the [Rapid7 Blog](https://www.rapid7.com/blog/post/2022/03/25/metasploit-weekly-wrap-up-154/).

### Payloads Manager Plugin

The Payloads Manager plugin keeps an archive of local or remotely fetched payload binaries under `~/.msf4/payloads/` and lets you activate one by creating a symlink into Metasploit's `data/meterpreter/` directory. This is useful when you are iterating on custom Meterpreter binaries and want to switch between archived payloads without manually copying files into the framework tree.

The available subcommands are:

* `payloads_manager list` shows the payloads currently stored in the local archive, including whether each payload is active.
* `payloads_manager add <path> [name]` copies a local payload into the archive and optionally records a name, description, and tags.
* `payloads_manager fetch <url> [name]` downloads a payload from an HTTP or HTTPS URL directly into the archive.
* `payloads_manager select <payload_id>` activates a stored payload by symlinking it into Metasploit's `data/meterpreter/` directory.
* `payloads_manager unselect <payload_id>` deactivates an active payload by removing its symlink.
* `payloads_manager remove <payload_id>` deletes a payload from the local archive.
* `payloads_manager help` prints the built-in usage summary.

IMPORTANT: If the name is not provided, the file name must match the name of the item to be dropped in `data/meterpreter/` (e.g. `metsrv.x64.dll` for a Windows x64 Meterpreter server payload). If the name is provided, the file will be symlinked with that name instead. For example, if you have a custom compiled payload named `custom_metsrv.x64.dll` but want to symlink it as `metsrv.x64.dll`, you can run `payloads_manager add /path/to/custom_metsrv.x64.dll metsrv.x64.dll` and then select it to have it symlinked as `data/meterpreter/metsrv.x64.dll`.

After loading the plugin, use `payloads_manager help` to view the available subcommands:

```msf
msf payload(windows/x64/meterpreter_reverse_tcp) > load payloads_manager 
[*] PayloadsManager plugin loaded.
[*] Successfully loaded plugin: payloads_manager
msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager list
Payloads
========

 ID        Name                       Description  Tags            Added At    Last Selected At  Status
 --        ----                       -----------  ----            --------    ----------------  ------
 1d7bce4cd7a8df83  metsrv.x64.dll                          arkari          1 days ago  1 days ago        Active
 594dccb0d253abb9  ext_server_stdapi.x64.dll               arkari          1 days ago  1 days ago        Active
 b270b3c5e097c33e  custom_loader.x64.bin                   direct_syscall  1 days ago  1 days ago        Active
 8fba8cb2be2257e9  custom_loader.x64.bin                   loader          7 days ago  1 days ago        Inactive

msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager unselect e9cf9064
[+] Payload 'metsrv.x64.dll' unselected and symlink removed.
msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager --help
[-] Unknown subcommand: --help
[*] PayloadsManager Help
[*] ==================================================
[*]   payloads_manager list
[*]   payloads_manager add <path_to_payload> [name] [--description <desc>] [--tags <t1,t2,...>]
[*]   payloads_manager fetch <url> [name] [--description <desc>] [--tags <t1,t2,...>]
[*]   payloads_manager select <payload_id>
[*]   payloads_manager unselect <payload_id>
[*]   payloads_manager remove <payload_id>
[*]   payloads_manager help
msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager add /home/<user>/Documents/dev/metasploit-payloads/c/meterpreter/output/metsrv.x64.dll metsrv.x64.dll --description "Standard mingw binary" --tags mingw,clean
[+] Payload added: metsrv.x64.dll (ID: c502a136eed80267)
[*]   Description: Standard mingw binary
[*]   Tags: mingw, clean
msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager list
Payloads
========

 ID                Name                       Description            Tags            Added At       Last Selected At  Status
 --                ----                       -----------            ----            --------       ----------------  ------
 594dccb0d253abb9  ext_server_stdapi.x64.dll                         arkari          1 days ago     1 days ago        Active
 b270b3c5e097c33e  custom_loader.x64.bin                             direct_syscall  1 days ago     1 days ago        Active
 8fba8cb2be2257e9  custom_loader.x64.bin                             loader          7 days ago     1 days ago        Inactive
 1d7bce4cd7a8df83  metsrv.x64.dll                                    arkari          1 days ago     1 days ago        Inactive
 c502a136eed80267  metsrv.x64.dll             Standard mingw binary  mingw, clean    5 seconds ago  Never             Inactive

msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager select c502a136eed80267
[+] Payload 'metsrv.x64.dll' selected and symlinked to /home/<user>/Documents/dev/metasploit-framework/data/meterpreter/metsrv.x64.dll
[*]   3 payload(s) currently active
msf payload(windows/x64/meterpreter_reverse_tcp) > payloads_manager list
Payloads
========

 ID                Name                       Description            Tags            Added At        Last Selected At  Status
 --                ----                       -----------            ----            --------        ----------------  ------
 594dccb0d253abb9  ext_server_stdapi.x64.dll                         arkari          1 days ago      1 days ago        Active
 b270b3c5e097c33e  custom_loader.x64.bin                             direct_syscall  1 days ago      1 days ago        Active
 c502a136eed80267  metsrv.x64.dll             Standard mingw binary  mingw, clean    36 seconds ago  16 seconds ago    Active
 8fba8cb2be2257e9  custom_loader.x64.bin                             loader          7 days ago      1 days ago        Inactive
 1d7bce4cd7a8df83  metsrv.x64.dll                                    arkari          1 days ago      1 days ago        Inactive

msf payload(windows/x64/meterpreter_reverse_tcp) > 
```

If you already host a payload artifact elsewhere, use `payloads_manager fetch <url>` instead of `add` to download it directly into the archive before selecting it.
