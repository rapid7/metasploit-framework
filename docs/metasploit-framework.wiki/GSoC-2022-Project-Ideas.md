GSoC Project Ideas in no particular order. When you've picked one, take a look at [[How-to-Apply-to-GSoC]] for how to make a proposal.

Mentors: [@zerosteiner](https://github.com/zerosteiner), [@jmartin-r7](https://github.com/jmartin-r7), [@gwillcox-r7](https://github.com/gwillcox-r7)

Slack Contacts: @zeroSteiner, @Op3n4M3, @gwillcox-r7 on [Metasploit Slack](https://metasploit.slack.com/)

For any questions about these projects reach out on the Metasploit Slack in the `#gsoc` channel or DM one of the mentors using the Slack contacts listed above. Note that mentors may be busy so please don't expect an immediate response, however we will endeavor to respond as soon as possible. If you'd prefer not to join Slack, you can also email `msfdev [@] metasploit [dot] com` and we will respond to your questions there if email is preferable.

## Enhance Metasploit Framework

### HTTP-Trace enabled login scanners

Current login scanners are not enabled to support the HTTP-Trace options, this options is current exposed in the `Exploit::Remote::HttpClient` mixin and not available in login scanners. This functionality would aid module writers in debugging and testing initial module implementations as well as enable end users to provide more verbose details for error reports. Changes to enable this support will need careful validation and testing as a large number of modules would be potentially impacted by the revision.

Size: Medium  
Difficulty: 3/5

### Rest API Pagination

Metasploit provides two API interaction services, a Rest API service and an RPC service. Previous efforts have wrapped and exposed the RPC service as JSON responses available from the Rest API endpoint. This wrapping did not account for possible large responses that may benefit from pagination. A previous contributor attempted to add this functionality for a [limited set of RCP commands](https://github.com/rapid7/metasploit-framework/pull/13439) however review identified that the changes would introduce changes to the documented public API and also introduce inconsistency within the API responses resulting in a fluctuating public API. Modern pagination would be beneficial to increasing user adoption of Rest API services provided it can be implemented consistently and either maintain compatibility of the existing public RPC service or generate a one time migration across all exposed public APIs.

Size: Large  
Difficulty: 4/5

### LDAP Capture Capabilities

Metasploit's LDAP service mixin provides a service to enable interaction over the LDAP protocol. The current implementation is the bare minimum to enable support for attacking the [2021 Log4Shell vulnerability](https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell?referrer=msf_docs). Enhancement/Extension of the mixin to enable various additional LDAP features would enable extended usage of this service for additional tasks. Support for various protocol level authentication methods would allow Metasploit to intercept and log authentication information. Specific items of interest are [SPNEGO](https://en.wikipedia.org/wiki/SPNEGO) and [StartTLS](https://ldapwiki.com/wiki/StartTLS) support to enable compatibility with the widest variety of clients and a new capture module that log authentication information from clients.

Size: Medium  
Difficulty: 3/5

### Enhanced LDAP Query & Collection

When performing security assessment on a network with centralized login such as LDAP or Active Directory these services are sometimes exposed directly on the network. While Metasploit has capabilities to collect various pieces of information from these services when a user has been able to gain code execution inside a target system by utilizing tooling such as `Sharphound` or by leveraging SMB services via the `secrets_dump` module, these methods are somewhat indirect. A network base capability to query exposed services may have value. An interactive terminal plugin allowing users to connect directly to LDAP or Active Directory providing capabilities similar to the existing `requests` plugin could enable users search for valuable information in these services without the need to compromise a target or interact with a secondary service. 

Size: Medium/Large (Depends on proposal)  
Difficulty: 3/5

### Improving post-exploit API to be more consistent, work smoothly across session types

The Metasploit post-exploitation API is intended to provide a unified interface between different Meterpreter, shell, PowerShell, mainframe, and other session types. However, there are areas where the implementation is not consistent, and could use improvements:

 * Shell sessions do not implement the filesystem API that Meterpreter sessions have
 * When a shell session is in a different language, e.g. Windows in French, the post API does not find the expected output. Add localization support for these.
 * Simple commands like 'cmd_exec' are fast in Shell sessions but are relatively slow in Meterpreter sessions. Add an API to make Meterpreter run simple commands more easily.

Size: Medium/Large (Depends on proposal)  
Difficulty: Varies

### Improve the web vulnerability API

This would follow up on the Arachni plugin PR <https://github.com/rapid7/metasploit-framework/pull/8618> and improve the Metasploit data model to better represent modern web vulnerabilities. This project would require knowledge of data models, types of modern web vulnerabilities, and experience with web app security scanners.

Size: Large  
Difficulty: 4/5

### Data Visualization

Enhance existing Metasploit Goliath dashboard that allows observation of an active engagement. Data visualization would include, but not be limited to: host node graph with activity indicators and heat maps. The main idea here is to create a visualization tool that helps users understand data that has been gathered into Metasploit during usage in some useful way. Proposals should note where the service will live, how a user will use the service, and how you will provide a maintainable and extendable consumer for the data that is exposed.

See [Metasploit 'Goliath' Demo (msf-red)](https://www.youtube.com/watch?v=hvuy6A-ie1g&feature=youtu.be&t=176) for a demo video of Goliath in action. You can also read more on Metasploit Goliath at [[Metasploit-Data-Service-Enhancements-(Goliath)|./Metasploit-Data-Service-Enhancements-Goliath]

Size: Medium/Large (Depends on proposal)  
Difficulty 3/5

## Submit your own

If you want to suggest your own idea, please discuss it with us first on [Slack](https://metasploit.com/slack) in the `#gsoc` channel to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.
