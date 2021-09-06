* **store_loot()** - Used to store both stolen files (both text and binary) and "screencaps" of commands such as a ```ps -ef``` and ```ifconfig```. The file itself need not be of forensic-level integrity -- they may be parsed by a post module to extract only the relevant information for a penetration tester.

* **report_auth_info()** - Used to store working credentials that are immediately reusable by another module. For example, a module dumping the local SMB hashes would use this, as would a module which reads username:password combinations for a specific host and service. Specifically, merely "likely" usernames and passwords should use store_loot() instead.

* **report_vuln()** - Auxiliary and post modules that exercise a particular vulnerability should report_vuln() upon success. Note that exploit modules automatically report_vuln() as part of opening a session (there is no need to call it especially).

* **report_note()** - Modules should make an effort to avoid report_note() when one of the above methods would be a better fit, but there are often cases where "loot" or "cred" or "vuln" classifications are not immediately appropriate. report_note() calls should always set a OID-style dotted :type, such as domain.hosts, so other modules may easily find them in the database.

* **report_host()** - Reports a host's liveness and attributes such as operating system and service pack. This is less common because other reporting methods already do this, such as ```report_service```, ```report_exploit_success```, ```report_client```, ```report_note```, ```report_host_tag```, ```report_vuln```, ```report_event```, ```report_loot```, etc. Try not to repeat it.

* **report_service()** - Reports a new service (port) that's been detected by your module.

* **report_client()** - Reports a client running a host, such as a web browser.

* **report_web_site()** - Reports a website, and must be tied to an existing ```:service```. If there is no ```:service```, you will have to supply ```:host```, ```:port```, ```:ssl```.

* **report_web_page()** - You can use this if your module discovers a webpage that look interesting.

* **report_web_form()** - You can use this if your module discovers web forms that look interesting.

* **report_web_vuln()** - Reports a web application vulnerability. Exploits don't really need to use this. It's more suitable for auxiliary modules that exploit a bug that determines that it is vulnerable.

* **report_loot()** - Very rarely, modules might actually want to export loots without using store_loot(). Typically they do this with Ruby's file IO, but this won't be logged in the database so can't be tracked by Metasploit Framework. In that case, a ```report_loot()``` is needed. However, 99.9% of the time you should be using ```store_loot()```.

### References

- [[Guidelines for Accepting Modules and Enhancements]]
- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary/report.rb>
