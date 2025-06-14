GSoC Project Ideas in no particular order.

Mentors: [@busterb](https://github.com/busterb), [@zerosteiner](https://github.com/zerosteiner), [@timwr](https://github.com/timwr), [@asoto-r7](https://github.com/asoto-r7), [@jmartin-r7](https://github.com/jmartin-r7), [@pbarry-r7](https://github.com/pbarry-r7), [@mkienow-r7](https://github.com/mkienow-r7), [@jbarnett-r7](https://github.com/jbarnett-r7)

## Enhance Metasploit Framework

### Improving the Post-exploit / Meterpreter functionality

Examples could include:
 * Sending keystrokes and mouse movement to a Meterpreter session
 * HTML based VNC style session control
     e.g https://github.com/rapid7/metasploit-framework/pull/9196 but accepting user input from the browser
 * Playing (streaming?) sounds to a Meterpreter session
 * Implementing the streaming record mechanism from more Meterpreter sessions 
 * Text-to-speech and volume control
 * Fun behaviors
    - Ejecting the CD-ROM drive
    - Flipping the screen upside down
    - Changing screen colors
    - Turning the monitor on/off
    - Ordering donuts 
 * MessageBox or live chat functionality
    (e.g "This machine is vulnerable to MS17-010, you must run Windows Update!")
 * Overlaying an image or even HTML on the user interface

Difficulty: Varies

### Improving post-exploit API to be more consistent, work smoothly across session types

The Metasploit post-exploitation API is intended to provide a unified interface between different Meterpreter, shell, powershell, mainframe, and other session types. However, there are areas where the implementation is not consistent, and could use improvements:

 * Shell sessions do not implement the filesystem API that Meterpreter sessions have
 * When a shell session is in a different language, e.g. Windows in French, the post API does not find the expected output. Add localization support for these.
 * Simple commands like 'cmd_exec' are fast in Shell sessions but are relatively slow in Meterpreter sessions. Add an API to make Meterpreter run simple commands more easily.

Difficulty: Varies

## Add meta-shell commands

Shell sessions typically expose a direct connection to a remote shell, but are lacking a number of nice features such as the ability to stop a remote command, background a command (this could be advanced or depend on the underlying session), or to even lock the session. This project would implement some pre-processing hooks to shell sessions so that job control could be added by default (allowing backgrounding of commands), meta-commands like 'background' and 'sessions' could be added as well.

Difficulty: 3/5

### Improve the web vulnerability API

This would follow up on the Arachni plugin PR <https://github.com/rapid7/metasploit-framework/pull/8618> and improve the Metasploit data model to better represent  modern web vulnerabilities. This project would require knowledge of data models, types of modern web vulnerabilities, and experience with web app security scanners.

Difficulty: 4/5

### Session-style module interaction

Metasploit has the concept of 'sessions' where a connection context can define its own set of console operations. E.g. if you interact with a session, Metasploit switches to a specific subconsole for interaction. It would be nice as an alternative to 'action' for auxiliary modules, or as a way to merge related modules, to simply interact with the module.

Difficulty: 3/5

### Integration plugin with a 3rd-party post-exploit framework

Connect a 3rd-party post-exploitation framework with Metasploit, such as Empire, Pupy, or Koadic, so that Metasploit can view and interact with sessions outside of its own types. Being able to use outside stagers in exploits, or adding the ability to 'upgrade' a session to an outside session type are other possibilities.

Difficulty 3/5

## Enhance Metasploitable3

### Create a Simulated Active Directory Domain

Expand functionality of the existing Windows 2008 VM to act as a domain controller. The setup should include a number of users of varying roles, multiple group policy objects and settings, and logon scripts or application deployments. Considerations should be taken on how and where to include purposeful vulnerabilities within these settings.

Difficulty 2/5

### Configure a Mock Corporate Network

Currently metasploitable3 consists of two separate virtual machines with all currently configured vulnerable services available with a simple network connection. This should be expanded to include a larger number of VMs with services spread across them to better simulate a real world environment. Considerations must be taken for deploying this on systems with varying hardware availability, or look into different cloud providers.

Difficulty 4/5

### Add Monitoring Capabilities Between VMs

Metasploitable3 is already a playground from an attacker's point of view, but how can we make it valuable from a defender's perspective. Research various network monitoring and detections solutions and implement them across the mock network. Set up a new "NOC" VM for keeping track of activity and watching for intrusion. This goal is to make it fairly simple for anyone to set up a red team vs blue team mock environment.

Difficulty 5/5

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
