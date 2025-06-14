# Acceptance Guidelines

Contributions from the open source community are the soul of Metasploit, and we love evaluating and landing pull requests that add new Framework features and content. Metasploit Framework has many tens of thousands of users who rely on daily, consistent, and error-free updates. Because of this, Metasploit's core developers have adopted a fairly high standard for pull requests that add new Framework functionality and Metasploit modules. In order to encourage open and transparent development, this document outlines some general guidelines for Metasploit contributors and developers. Adhering to these guidelines maximizes the chances that your work will be merged into the official Metasploit distribution packages.

## Module Additions

Most open source community support for Metasploit comes in the form of Metasploit modules. The following should be considered for acceptance; note that these are guidelines and not categorical imperatives ("should"s, not "must"s), since there are always exceptions to the norm-especially when it comes to novel new attacks and techniques.

Modules should pass [msftidy.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/msftidy.rb) and adhere to the [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md) guidelines. Both are distributed with Metasploit. See [[Style Tips]] for some information on how to take some of the headache out of whitespace issues.

Modules should have a clear and obvious goal: Exploits should result in a shell. Post modules should result in privilege escalation or loot. Auxiliary modules are an "Everything else" category, but even they should be limited to a well-defined task (e.g., information gathering to enable an exploit or a post module).

Modules should not launch other modules, given the complexity of setting multiple payloads. Such actions are usually automation tasks for an external UI.

Denial of Service modules should be asymmetric and at least have some interesting feature. If it's comparable to a synflood, it shouldn't be included. If it's comparable to Baliwicked, it should be included. Modules that hover the line, such as slowloris, may be included with some justification.

Modules should be able to function as expected with minimal configuration. Defaults should be sensible and usually correct. Modules should not depend on exact timing, uncontrollable heap states, system DLLs, etc. All memory addresses (ie. a JMP ESP, or a ROP gadget) should be part of the metadata under 'Targets', and documented (what instructions it points to, and what DLL). If the exploit is against a specific hardware (e.g., routers, PLCs, etc), or against a software that's not free (and no trial/demo available), please remember to submit a binary packet capture (pcap-formatted) along with the module that demonstrates the exploit actually works.

Please don't use the alphanum encoder as a way to avoid BadChar analysis. Modules which set the `EncoderType` field in the payload as a way to avoid doing real BadChar analysis will be rejected. These modules are nearly always unreliable in the real world.

Exploit ranking definitions can be found on the [[Exploit Ranking]] page.

Exploit modules should implement a `check()` function when this is trivial to do so. Versions exposed through banners or network protocols should always result in a `check()` routine when a patch is available that changes this version.

If a module (auxiliary or post) obtains some sort of information from the victim machine, it should store that data using one (or more) of the following methods:

* `store_loot()`: Used to store both stolen files (both text and binary) and "screencaps" of commands such as a `ps -ef` and `ifconfig`. The file itself need not be of forensic-level integrity -- they may be parsed by a post module to extract only the relevant information for a penetration tester.

* `report_auth_info()`: Used to store working credentials that are immediately reusable by another module. For example, a module dumping the local SMB hashes would use this, as would a module which reads username:password combinations for a specific host and service. Specifically, merely "likely" usernames and passwords should use `store_loot()` instead.

* `report_vuln()`: Auxiliary and post modules that exercise a particular vulnerability should `report_vuln()` upon success. Note that exploit modules automatically `report_vuln()` as part of opening a session (there is no need to call it especially).

* `report_note()`: Modules should make an effort to avoid `report_note()` when one of the above methods would be a better fit, but there are often cases where "loot" or "cred" or "vuln" classifications are not immediately appropriate. `report_note()` calls should always set a OID-style dotted `:type`, such as `domain.hosts`, so other modules may easily find them in the database.

Modules should take advantage of the normal Metasploit APIs. For example, they should not attempt to create their own TCP sockets or application protocols with native Ruby; they should mediate sockets through `Rex` and `Rex::Proto` methods instead. This ensures compatibility with the full set of Framework features, such as pivoting and proxy chaining.

Web application attacks are generally uninteresting (SQLi, XSS, CSRF), unless the module can reliably result in a shell or exercise some kind of useful information leak. Even in that case, the module should "just work," as above.

Web application attacks should be limited only to popular, widely deployed applications. For example, a SQLi module against a popular CMS that results in a shell on the CMS machine would be welcome. A module that causes a private Facebook profile to become public would not (Facebook has exactly one deployed instance).

Web application attacks should implement an HttpFingerprint constant.

Modules should only list targets that **you** actually tested the exploit on. Avoid assuming it works on a specific system if it has never been tested on it. Comments above the target entry indicating additional information about a given target (language pack, patch level, etc) greatly assist other developers in creating additional targets and improving your module.

Modules can exercise unpatched and undisclosed vulnerabilities. However, Rapid7 is happy to assist with the disclosure process by following the Rapid7 policy. This policy provides a fixed 90-day window from when the vendor is contacted until the exploit is released. All vulnerabilities found by Rapid7 staff follow this process. The submitter will receive full credit for the vulnerability and the resulting exploit module regardless of how disclosure is handled.

## Framework Enhancements

Generally, new functionality to the Metasploit Framework should start life as a plugin. If the functionality becomes useful and popular, we can integrate it more closely, add RPC API exposure, and so on, but it should be well-tested by the community before then.

Automating a series of discrete functions is generally /not/ the responsibility of the Framework. Automation should be accomplished through the API (see Metasploit Community/Pro, MSFGUI, etc). Past efforts with in-Framework automation prove this out. Components such as `db_autopwn` and `browser_autopwn` rarely did what users expected, and configuring these tools became a nightmare through increasingly complex sets of options and arguments. Automating the Framework is easy and should stay easy, but the automation itself should live in resource scripts and other external front-ends to the Framework itself. 

Console functionality should have a focus on exploit and security tool development, with the exploit developer as the typical user. End users should be pointed to an interface such as the Community Edition or MSFGUI and should not expect much in terms of user-friendliness from the console. The console should be considered a debug mode for Metasploit and as close to bare-metal functionality as possible. 

External tools, such `msfpayload` and `msfvenom`, are designed to make exploit development easier and exercise specific techniques. We are happy to continue evaluating tools of this nature for inclusion in the Framework; these should be accompanied by documentation (!), how-to tutorials for quick start, and other helpful text.