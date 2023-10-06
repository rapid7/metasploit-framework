This document is our live wishlist of features and changes for the Metasploit Meterpreter payloads. The majority of this list came from a survey sent out to the community in early 2015. If you plan to work on one of these features, please add a note to the item, and reference any open tickets or pull requests that are relevant. This document only contains survey suggestions that were specific to Meterpreter. Duplicate and similar items have been combined.

Items currently in development have been marked [**IN PROGRESS**]

Items landed to master have been marked [**DONE**]


Related open tickets (slightly broader than Meterpreter):
 * [**DONE**] [Make User-Agent easier to control across modules and more consistent](https://github.com/rapid7/metasploit-framework/issues/4933)
 * [**IN PROGRESS**] [Comprehensively refactor Windows reverse_http stagers](https://github.com/rapid7/metasploit-framework/issues/4895)
 * [**DONE**] [Python reverse HTTPS stager](https://github.com/rapid7/metasploit-framework/pull/4978)
 * [**DONE**] [Port windows reverse_tcp & bind_tcp to Metasm](https://github.com/rapid7/metasploit-framework/pull/4939). Was later found to be implemented in https://github.com/rapid7/metasploit-framework/pull/5214.

### Meterpreter Platform Support
 * Mac Meterpreter
 * iOS Meterpreter
 * PHP Meterpreter should have equivalent functionality to Win32
 * Python Meterpreter should have equivalent functionality to Win32
 * POSIX Meterpreter should have equivalent functionality to Win32 (extract it from Win32 codebase)
 * Powershell Meterpreter
 * Some users indicated that the Python/PHP Meterpreters were important because the POSIX/Linux Meterpreter was not working for them

### Mimikatz Integration
 * In-memory pass-the-hash (basically this runs a process as "netonly" I believe, then injects real credential hashes supplied by the user in order to perform network based auth to things with only a hash)
 * Exporting of certificates, keys, and tickets in base64 format (already supported) then down to real files on disk for the attacker [info](https://github.com/gentilkiwi/mimikatz/wiki/module-~-standard#base64)
 * Add on-target minidump extraction
 * Add sekurla::searchpasswords
 * Expand Mimikatz and contribute back to it
 * Integration of Mimikatz with the credential database
 * Latest version of Mimikatz to be used as the plugin
 * It would be great to have a method to generate a golden ticket for a specific period of time (month, 6-months, year) rather than only 10 years.

### Meterpreter Pivoting
 * VPN Pivoting for Framework  (WinPcap still better than nothing)
 * Reverse pivoting from the target machine back to the attacker (TCP/UDP) . For many years I've asked for this feature. Basically Meterpreter needs to be able to say, listen on port 8080 on victim 1 and it go through the Meterpreter session to port whatever (9060) on the attacker's machine or a designated alternate IP. then, whenever someone hits that port it's auto forwarded through the session. This could help out a lot for SMB capture, Post exploitation phishing, and other things like setting a user's proxy to use your forwarded port instead of the corporate proxy.
 * Improved pivoting speed and latency
 * Pivoting that is reliable and works well with different transports.  In particular, I want the ability to pivot one session through another even if the first session is reverse_tcp or reverse_https, regardless of the second sessions transport.  This will be difficult without installing drivers, but I would like several useful, working transports that I know I can pivot reliably with.
 * Carry portforwards and other channels along with a migrate.

### Privilege Escalation
 * Allow privilege escalation modules to increase the privileges of the current session instead of firing off a new session.
 * Automated privesc for all platforms - not just Windows.
 * Implement a "privup" command that is similar to getsystem which automatically tries to get higher privs using local exploits. Allow the user to specify a "force" flag to automatically try "dangerous" privilege escalations (kernel mode, etc)
 * Make the "local" modules more seamlessly accessible inside Meterpreter without requiring sending your session to background and running a local module separately against it.Would be nice to have a built-in Meterpreter command called "local" with tab complete that would list the local modules relevant to that platform/arch - then running one of the local modules auto selects your current session, spawns a new metepreter session and transfers you over to that session automatically if successful with a clear message/indication that your now in a new elevated Meterpreter session.


### Remote File Access
 * [**DONE**] Console/Meterpreter: Support for uploading, downloading, deleting, renaming, and listing files using UTF-8 input and showing UTF-8 output, converting this in the Meterpreter payload as necessary to support accessing unicode paths on the target.
 * [**DONE**] Console: The ls command should support wildcards in the directory listing, ex: ls \*.csv
 * [**DONE**] Console: The ls command should support sorting files by date, name, or size
 * [**DONE**] Console: The ls command should support listing MSDOS 8.3 (short) names if available on Windows
 * [**DONE**] Console: The download command should support filtering files based on a wildcard match (recursively, too)
 * [**DONE**] Console: The download command should mirroring an entire remote file system to a local directory (names, paths, and timestamps)

### Meterpreter Features
 * Direct Powershell integration on Windows (load & run .NET runtimes from inside Meterpreter)
 * Remote (target-side) scripting
 * Builtin userland persistence
 * Builtin rootkit/bootkit payload persistence
 * Create payloads that only "install" on specific computers (based on hardware, windows domain, etc)
 * Acquire a physical RAM image without touching the disk. This currently requires uploading winpmem[64].sys to windows\system32 and invoking it through post/windows/manage/driver_loader. As loaded winpmem.sys exposes the RAM as disk device I can then suck it through post/windows/manage/nbd_server. Please make this possible without dropping winpmem.sys to system32 folder if possible
 * Manage multiple Meterpreter processes as one session as described in #4715. Many times there have been situations where a keyscan, or sniffer was going and something else occurred that required migration or cancelling to perform an action. "Installing" jobs in processes less likely to die would allow a pentester to still move around as needed but also be able to have persistent tasks going. A pipe dream of this feature would be to install a "rev2system" jobs whereby I could migrate to a low priv status for accessing Cryptolib encrypted storage but also get back to SYSTEM when I'm done without needing to pop a shell again. Another pipe dream here would be to also have jobs that if the user logged out, then back in the next day and I had a shell come back then, I could re-attach to my running jobs and get their results

 * PrependTokenSteal / PrependEnvironmentSteal: Basically with proxies and other perimeter defenses being SYSTEM doesn't work well. This would be an addition to a payload that would work to execute as SYSTEM but would then locate a logged in user and steal their environment to call back to the handler. Very useful when pivoting around with PSEXEC
 * Binary installed death dates: A way putting a date in a binary where after that date the binary no longer functions would be useful and possibly even perform self-deletion. Time zones would be a tricky matter, but is something handled by many programmers already (probably just not in shellcode)
 * Allow Meterpreter sessions to resolve L3 addresses (#4793)
 * Track whether or not the current session has admin credentials (#4633)d
 * Support Metasploit-side zlib compression of sessions
 * Being able to use Meterpreter instances to easily forward commands & exfil
 * Automatic cleanup and removal of session and any recorded persistence after predetermined amount of time (server-side)
 * Change desktop/phone background
 * Remote mouse control
 * Play sound on the remote system
 * Read words outloud via text to speech on the remote system
 * Volume control
 * RSS feed from reverse_http(s) mult-handler that I can connect a RSS reader to (or something like IFTTT) and get notices when new sessions are created
 * MessageBox popups
 * Call the system "open" command easily (ShellExecute on windows, launch intent on Android)
 * Gather credentials from Google Chrome
 * LNK (binary) modification: Editing a LNK file's ICON location (for SMB capturing), "Starting Directory" (for DLL injection) or target binary would make some post exploitation tasks easier
 * "Pinned" app modification: Knowing which apps are pinned, and what they link to (be it taskbar or start menu) would be useful intelligence, but also being able to modify the target of these links would be better and a very easy user-land persistence. (Run this && the real thing you want)
 * Remote Registry automation: Remotely editing or reading the registry of a remote system works currently (sometimes) but it has no smarts about if the Remote Registry service is on or not. It would be nice to automate the starting and stopping of the remote registry service as well as possibly warning the user if they are attempting to do this as SYSTEM (probably going to fail). The use case for this is installing persistence on lots of systems quickly as well as reading user lists, MRUs and other intelligence important keys. (like finding a system with the puTTY keys)
 * "ps" and "kill" for remote systems: This would remove the need to drop to a shell and attempt to remember how to format "taskkill" and "tasklist"'s argument list. Tasklist also automatically removes the IPC$ connection after it's done so results in some annoying disconnected share viewing
 * Scheduled Tasks / AT: Many of the ways to pivot or stay persistent use AT or Scheduled Tasks, to do so. This functionality to do tasks both locally and on remote hosts would greatly decrease the number of times a pentester would need to drop to cmd.exe
 * [**DONE**] Execute with login credentials: When a user is no longer online it is overkill to PSEXEC (which would just net a SYSTEM shell anyways with MSF) and "RunAs" isn't supported since it requires a password at a prompt, so adding a simple CreateProcesWithLogon feature would help with reviving dead tokens [#4649](https://github.com/rapid7/metasploit-framework/pull/4649)
 * ListDrives: Most of the time shares and other drives rather than just C:\ are where important files are stored. This feature would list local storage (plus USB) and network storage (SMB connected drives with where they are connected from and as what user) to start, but this feature would need to grow to support "Cloud" drives as well, like Dropbox, Box, Google Drive, and SkyDrive.
 * Enumerables support in Railgun: Windows is full of "Enumerables" like EnumWindows that would be nice to have the ability to create code for. That example is bad since ExtAPI has EnumWindows now but the argument doesn't go away for railgun
 * DACL / Permissions enumeration: This is just needed in general for privilege escalation enumeration, share permissions, and reporting ("Why did you have access to this share, it was only supposed to be for X")
 * Gina/SSP support: This would probably need to be an injected "job" but the basic premise is an in-memory load of a SSP or inject into Gina so when a new login happens against the system a set of clear text credentials are captured. 2 extremely use cases would be on a terminal server, or a server that no one is logged into at the time of infection due to time zone or operating hour differences
 * Websnapshot: Currently there isn't a way to weed out web applications once in a network. This feature would, using IE, or another method be able to generate a screenshot of what a page looks like in a browser (given a PROTOCOL/URL/PORT). Biggest requirement is auto-accepting any self signed SSL certs and showing when authentication is required.
 * On-target resource cloning: Allowing a pentester to drop a binary and clone the ICON (in particular) of a binary would add to the stealthiness of an operation and add attack opportunities that weren't previously thought plausible
 * Scatterbomb: Persistence is difficult, and making sure your session doesn't die because you chose the wrong process to migrate into or the user exited that process because the PDF looked hung. This would work by attempting OpenProcess on every process or a select list of processes and inject Meterpreter threads into them. But it would rely on the Mutex feature so that only one would be calling back at a time. Basically allowing for a resilient semi-persistent Meterpreter session that would save you from yourself when you accidentally type exit on the Meterpreter> prompt instead of your other terminal
 * Mutex checking binary exports: This follows up with the scatterbomb but essentially when installing persistence as a pentester I only install one because installing more than one would raise the noise level of a compromised host. If the binary/callback would check a mutex before doing anything and looping based on a timeout that even better.
 * OLE / Office Controls: This is basically an open ended feature request asking for support of for Office, mostly Outlook (like read newest emails, search email, etc).
 * Configurable character set conversation for Shell sessions and channels.  When spawning a windows shell from meterpreter, on a host that uses a German version of windows, all the special characters (e.g. öäü) are broken, i.e. they are either not rendered at all, or replaced with that default "character not found" unicode character. Forcing the terminal emulator to use cp850 made it work for now.


### Metepreter Stager Support
 * [**DONE**] Network error tolerant versions of existing stagers
 * [**DONE**] Tagged stagers that send the payload type, arch, platform during the staging process to enable shared listeners
 * [**DONE**] Stagers that contain an embedded unique ID that can be used to identify which payload triggered what session
 * [**DONE**] Stagers that are "stageless" for Meterpreter (include the entire main Meterpreter payload, plus any required extensions). In situations of high network latency or extreme network detection a non-staged exe is the only way to go. Ulta-met is a project that does this but isn't as stable or easy to work with as if it were just built into the binary creation options.
 * [**DONE**] Stagers that are "stageless" for Meterpreter and include all potential functionality (all extensions)

### Meterpreter Transport Flexibility
 * [**DONE**] Support for changing the transport (host, port, URL) of a live session to a new endpoint or protocol
 * [**DONE**] Support for multiple transports for the initial session, using the first transport that works
 * [**DONE**] Support for multiple endpoints across multiple transports for the initial session
 * [**DONE**] Support for automatic switching between multiple transports while the session is running
 * [**DONE**] Support for user-configured callback frequency and endpoint rotation
 * Support for Tor tunneling to .onion and internet-facing listeners
 * Support for time-based callback, such as limiting callbacks to certain times of the day.
 * Support for P2P style callbacks. Gossip protocol to find other Meterpreters on the network and use them as exfiltration point. This callback would reduce the amount of endpoints that would call "out" to a handler to 1. Whoever the "master" was. All comms would automatically (because, math) find and delegate this master and finally send through the master all of their comms. This could happen over a named pipe, or a forwarded port or something. (DHT?)
 * Support for DNS A/TXT transports
 * Support for UDP transports
 * Support for ICMP transports
 * Support for TLS encrypted bind listeners
 * Support for HTTP application listener (ie CGI mode Meterpreter session, tomcat servlets, etc)
 * Support for third-party communication transports (Github, Twitter, pastebin, etc)
 * Support for XMPP transports. Many organizations use IM and chat clients internally and support them going outbound. reverse_tcp being stopped for the most part these days and more and more catching reverse_http(s) due to proxies, this might become the next outlet. Possibly using server that are already established in the industry ;-) but mainly supporting XYZ jabber server as a pass through. This would probably be a very big piece of shellcode as I don't believe any Windows OSs support XMPP out of the box.
 * Support for IE callback: One method deployed by some more infamous malware is to only communicate when IE is running and surfing and only by hooking IE to send comms. This callback would operate very much the same and would support any kind of proxy by default as IE does.
 * Support for Outlook callback:  This callback would use email back and forth either directly to a MSF run SMTP server or through other services, but the C2 channel would be locally (not on the exchange filter system) auto-filtered to a non-visible folder (using PidTagAttributeHidden). This type of comms would greatly increase the lag time supported in Metepreter simply due to the inherent lag in email.

### Meterpreter HTTP Transport Options
 * [**DONE**] Create a whitelist of allowed URLs on the handler, have these persistent between metasploit runs
 * [**DONE**] Indicate whether a given handler should silently accept, accept and report, or drop connections using unregistered URLs
 * [**DONE**] Whitelisted URLs should be referencing using an alias, stored persistently with the URL
 * [**DONE**] Session listing output should indicate what URL and URL alias a particular session is associated with
 * [**DONE**] URLs can be anywhere from 30 to 128 bytes long

### Meterpreter Proxy Support
 * [**DONE**] Use Windows Credentials with NTLM Authentication to connect via System Proxy back to attacker
 * If Meterpreter executes as system - option to find a user, and use that users proxy settings for comms (temporarily or cleanup on exit) - maybe something like RunAsCurrentUser
 * [**DONE**] Better proxy support and the ability to sleep. Still more to done on burstable updates

### Communication Protection
 * Authenticated callbacks: This is pretty straight forward, when a pentester no longer controls the IP they were attacking from and failed to clean up every binary and phishing email there is a chance of compromise by proxy. The problem was somewhat solved with  SessionExpirationTimeout and SessionCommunicationTimeout but both of them are loaded in the stage, not hard coded into any binary built, so it's very easy to get into this situation. Authenticated callbacks would allow a pentester to add a small layer of protections if this event were to happen and a callback from a client was sent to an IP no longer in the pentester's control
 * Embedded TLS cert or hash of cert to verify Meterpreter instance on the Metasploit side
 * [**DONE**] Embedded TLS cert or hash of cert to verify Metasploit instance on the Meterpreter side
 * Embedded password to verify Meterpreter instance on the Metasploit side (challenge-response)
 * Embedded password to verify Metasploit instance on the Meterpreter side (challenge-response)
 * [**DONE**] Enable TLS verification to verify Metasploit instance on the Meterpreter side
 * [**DONE**] Allow open, relaxed, strict modes of payload authentication (everything, everything but flag unauthorized, drop non-authorized)

### Communications Evasion
 * Emulation of common web application traffic when using HTTP-based transports
 * Change web application traffic emulation fingerprints on the fly when using HTTP-based transports
 * [**DONE**] Sleeping for a specified period of time before reconnecting to Metasploit
 * [**DONE**] Automatic shutdown/cleanup after a specified amount of time has passed
 * Traffic shaping or malleable communications, especially for HTTP(S), can be very useful for blending in, or even for adversary simulation. See Maligno (OSS - <http://www.encripto.no/tools/>)
 * Malleable network signatures in general
 * Malleable file artefacts - Make Meterpreter look like PlugX / Poison Ivy / etc.
 * Stealthier network comms (C2 DLL inject into web browser)
 * Better support to automatically identify applications that use a corporate proxy that allows outside connections and then leverage this application's features
 * Emulate various real world malware
 * Being able to use Meterpreter instances to easily forward commands & exfil
 * Supporting a set URI path for reverse_http(s), so you can use other webservers as a reverse proxy.

### Session Handlers
 * [**DONE**] Generate a unique ID for each session (target-side)
 * [**DONE**] Generate a unique ID for each generated payload  Backdooring/Persisting on more than 10 machines over months it gets very difficult to know when a host hasn't called back in a while or when a new host arrives. This would need not to be based on gateway, local IP, or any other transient information. This can be processed at any step as long as when STDAPI is loaded I can quickly identify if it's a system that I've known about, and how long it's been since I've seen it.
 * Shared listeners that can stage multiple payload architectures and platforms (using tags). Depends on new stagers and a new listener and unique IDs. [**IN PROGRESS**]
 * [**DONE**] Track the last time a given session checked in
 * Track user defined state data in the db, such as specific user / member of group logged in, specific shares open, certain tuple of IP:port in network connections (1.2.3.4 over 22 where 1.2.3.4 is an IP of interest)
 * Reconnecting payloads will have different IPs, take this into account for session methods (peerinfo/tunnelinfo, etc)

### Session Reliability
 * [**DONE**] Metasploit payloads should always restore connections if there is a network error unless the user explicitly kills the session
 * Improve reliability, encryption, authentication. Better integration for custom payloads.
 * Spawn a new session before running a module that could crash the current session (mostly privilege escalation, but some buggy post modules too [railgun])
 * Meterpreter should work robustly in a VM, on a cloud server, or through corp proxies

### Android Meterpreter Features
 * Android gather modules for auth tokens & sqlite databases (call logs, contacts,  email, etc)
 * [**DONE**] Android lock screen removal
 * Crack the lock screen hash to reveal the password, pin code or gesture
 * Remote screen control
 * Add record_mic_stream (trigger based on event, like phone call)
 * [**DONE**] Grab photos from front and rear cameras
 * Android desktop background, sound play, vibrate, screenshot
 * [**DONE**] Quickly grab GPS coordinates
 * Windows post module to install Meterpreter on any attached android devices
 * Better pivoting (e.g bridging between WiFi and 4g)
 * More root exploits
 * Dump browsing history and cookies
 * Comprehensive test suite (including rspec)
 * ARM/POSIX Meterpreter
 * [**DONE**] Support for native payloads in the addJavascriptInterface exploit

### Payload Generation
 * Msfvenom should support injecting into existing APKs for Android Meterpreter deployment. Otherwise, it's just an app the target installs for 10 seconds and removes after confirming it has no user interface, barely allowing the Meterpreter session to be created. [**IN PROGRESS**]
 * Msfvenom really needs to spit out some C# payloads. You can pretty easily modify some of the powershell ones to be C#, but there really ought to be a built in C# payload.
 * [**DONE**] Generated payloads should default to exiting the process when the shellcode completes
 * [**DONE**] Payload generation should allow named UUIDs to be injected into payloads


### Unit testing for payloads
 * Metasploit payload classes should have specs, new specs should be created when any class is changed if there isn't an existing spec.
 * Metasploit payload tests that can run in Github Actions, should be automatically tested end-to-end
 * Metasploit payload tests that can't run in GitHub Actions should be run by Jenkins and target a virtual machine (local or cloud-hosted).
 * Meterpreter payloads should test every advertised console command.
 * Meterpreter payloads should test a subset of the full APIs available.

### Meterpreter Specifications
 * These define compatibility, quality, and order of preference for Meterpreter payload modules, including stages and stages.
 * Payload Flags (for matching with exploits/generators/handlers):
   * Supports SSL
   * Supports ZLIB
   * Staged / Unstaged
 * Quality Rank (for prioritizing bugs/feature work):
   * Leverage using Rank system
   * Windows: Excellent
   * Python: Great
   * Java: Good
   * PHP: Normal
   * POSIX: Normal
 * Capabilities (queried post-stage to determine features):
   * Filesystem
   * Registry
   * Pivoting (sockets)
   * Pivoting vpn)
   * Process listing, kill, execute
   * Process memory read, write, injection
   * Migration
