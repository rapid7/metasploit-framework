GSoC Project Ideas in no particular order. When you've picked one, take a look at [[GSoC-2018-Student-Proposal]] for how to make a proposal.


### Submit your own

If you want to suggest your own idea, please discuss it with us first on [our mailing list](https://groups.google.com/forum/#!forum/metasploit-hackers) to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.

### Session-style module interaction

Metasploit has the concept of 'sessions' where a connection context can define its own set of console operations. E.g. if you interact with a session, Metasploit switches to a specific subconsole for interaction. It would be nice as an alternative to 'action' for auxiliary modules, or as a way to merge related modules, to simply interact with the module.

Difficulty: 3/5, Mentor: @busterb

### Integration plugin with a 3rd-party post-exploit framework

Connect a 3rd-party post-exploitation framework with Metasploit, such as Empire, Pupy, or Koadic, so that Metasploit can view and interact with sessions outside of its own types. Being able to use outside stagers in exploits, or adding the ability to 'upgrade' a session to an outside session type are other possibilities.

Difficulty 3/5, Mentor: @busterb

