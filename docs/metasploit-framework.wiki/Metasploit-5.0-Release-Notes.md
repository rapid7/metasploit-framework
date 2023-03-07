Metasploit Framework 5.0 has released!

Metasploit 5.0 brings many new features, including new database and automation APIs, evasion modules and libraries, language support, improved performance, and ease-of-use.

See the release announcement [here](https://blog.rapid7.com/2019/01/10/metasploit-framework-5-0-released).

The following is a high-level overview of Metasploit 5.0's features and capabilities.

* Metasploit users can now run the PostgreSQL database by itself as a RESTful service, which allows for multiple Metasploit consoles and external tools to interact with it.

* Parallel processing of the database and regular `msfconsole` operations improves performance by offloading some bulk operations to the database service.

* A JSON-RPC API enables users to integrate Metasploit with additional tools and languages.

* This release adds a common web service framework to expose both the database and the automation APIs; this framework supports advanced authentication and concurrent operations. Read more about how to set up and run these new services [[here|./Metasploit-Web-Service.md]].

* Adds `evasion` module type and libraries to let users generate evasive payloads without having to install external tools. Read the research underpinning evasion modules [here](https://www.rapid7.com/info/encapsulating-antivirus-av-evasion-techniques-in-metasploit-framework). Rapid7's first evasion modules are [here](https://github.com/rapid7/metasploit-framework/pull/10759).

* The `metashell` feature allows users to run background sessions and interact with shell sessions without needing to upgrade to a Meterpreter session.

* External modules add Metasploit support for Python and Go in addition to Ruby.

* Any module can target multiple hosts by setting RHOSTS to a range of IPs, or by referencing a hosts file with the `file://` option. Metasploit now treats RHOST and RHOSTS as identical options.

* An updated search mechanism improves Framework start time and removes database dependency.

## Get Metasploit 5.0

You can get Metasploit 5.0 by checking out the [5.0.0 tag](https://github.com/rapid7/metasploit-framework/releases/tag/5.0.0) in the Metasploit GitHub project.

Need a primer on Framework architecture and usage? Take a look at [our wiki here](https://docs.metasploit.com/), and feel free to reach out to the broader community [on Slack](https://metasploit.com/slack). There are also myriad public and user-generated resources on Metasploit tips, tricks, and content, so if you can't find something you want in our wiki, ask Google or the community what they recommend.

See all the ways to stay informed and get involved at <https://metasploit.com>.
