GSoC Project Ideas in no particular order. When you've picked one, take a look at [[How-to-Apply-to-GSoC]] for how to make a proposal.

Mentors: [@zerosteiner](https://github.com/zerosteiner), [@jmartin-r7](https://github.com/jmartin-r7)

## Enhance Metasploit Framework

### Retain active status of authentication tokens

Many testing techniques interacting with web servers such as `XSS` rely on ensuring authentication obtained on a target be kept active. A mechanism for registering and maintaining open authentications identified during a test for the duration of the console session may provide an additional utility to enable more modules to target techniques that need valid authentication to be maintained. One such authentication token would be data retained in a cookie for a web service. This project would lay the groundwork for registering gathered or generated authenticaion tokens against a target to be refreshed and sustained until a console exits, or in some cases across console restarts.

Difficulty: 2/5

### Improving post-exploit API to be more consistent, work smoothly across session types

The Metasploit post-exploitation API is intended to provide a unified interface between different Meterpreter, shell, powershell, mainframe, and other session types. However, there are areas where the implementation is not consistent, and could use improvements:

 * Shell sessions do not implement the filesystem API that Meterpreter sessions have
 * When a shell session is in a different language, e.g. Windows in French, the post API does not find the expected output. Add localization support for these.
 * Simple commands like 'cmd_exec' are fast in Shell sessions but are relatively slow in Meterpreter sessions. Add an API to make Meterpreter run simple commands more easily.

Difficulty: Varies

### Improve the web vulnerability API

This would follow up on the Arachni plugin PR <https://github.com/rapid7/metasploit-framework/pull/8618> and improve the Metasploit data model to better represent modern web vulnerabilities. This project would require knowledge of data models, types of modern web vulnerabilities, and experience with web app security scanners.

Difficulty: 4/5

### Data Visualization

Enhance existing Metasploit Goliath dashboard that allows observation of an active engagement. Data visualization would include, but not be limited to: host node graph with activity indicators and heat maps.

[Metasploit 'Goliath' Demo (msf-red)](https://www.youtube.com/watch?v=hvuy6A-ie1g&feature=youtu.be&t=176)

Difficulty 3/5

### Elasticsearch Datastore
Write Goliath data to Elasticsearch. Explore data visualization using Kibana.

Difficulty 3/5

## Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.
