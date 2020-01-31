GSoC Project Ideas in no particular order. When you've picked one, take a look at [[How-to-Apply-to-GSoC]] for how to make a proposal.

Mentors: @zerosteiner, @jmartin-r7, @pbarry-r7, @mkienow-r7, @jbarnett-r7

## Enhance Metasploit Framework

### Improving post-exploit API to be more consistent, work smoothly across session types

The Metasploit post-exploitation API is intended to provide a unified interface between different Meterpreter, shell, powershell, mainframe, and other session types. However, there are areas where the implementation is not consistent, and could use improvements:

 * Shell sessions do not implement the filesystem API that Meterpreter sessions have
 * When a shell session is in a different language, e.g. Windows in French, the post API does not find the expected output. Add localization support for these.
 * Simple commands like 'cmd_exec' are fast in Shell sessions but are relatively slow in Meterpreter sessions. Add an API to make Meterpreter run simple commands more easily.

Difficulty: Varies

### Improve the web vulnerability API

This would follow up on the Arachni plugin PR https://github.com/rapid7/metasploit-framework/pull/8618 and improve the Metasploit data model to better represent modern web vulnerabilities. This project would require knowledge of data models, types of modern web vulnerabilities, and experience with web app security scanners.

Difficulty: 4/5

### Session-style module interaction

Metasploit has the concept of 'sessions' where a connection context can define its own set of console operations. E.g. if you interact with a session, Metasploit switches to a specific subconsole for interaction. It would be nice as an alternative to 'action' for auxiliary modules, or as a way to merge related modules, to simply interact with the module.

Difficulty: 3/5

### Enhance Sql Injection Support

Enable faster implementation of SQL injection based explot modules by adding library support for common injection attack vectors. Currently very few sql injection exploits are implemented for Metasploit possibly due to the high complexity of building out injection queries and posting them to a vulnerable URI.

Difficulty: 3/5

## Conditionally Exposed Options

The Metasploit Framework's modules offer the core functionality of the project and these each use a set of datastore options for configuration. Many modules specify a particular system that they target or action that they provide. Modules should (but currently lack) the ability to expose and hide options through the UI based on either the target or action that they take. This would allow module developers to create more flexible modules without sacrificing user experience by exposing options that are irrelevant based on the current configuration.

Difficulty: 2/5

## Goliath

### Data Visualization

Enhance existing Metasploit Goliath dashboard that allows observation of an active engagement. Data visualization would include, but not be limited to: host node graph with activity indicators and heat maps.

[Metasploit 'Goliath' Demo (msf-red)](https://www.youtube.com/watch?v=hvuy6A-ie1g&feature=youtu.be&t=176)

Difficulty 3/5

### Elasticsearch Datastore
Write Goliath data to Elasticsearch. Explore data visualization using Kibana.

Difficulty 3/5

## Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.
