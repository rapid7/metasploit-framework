List of potential major features (things that would make major breaking changes) for MSF6:

## External payload listeners

Listeners, rather than being integrated straight into `msfconsole`, run as an independent process that communicates with msfconsole (1 or more users) over RPC similar to the msfdb_ws (Metasploit Database Web Service). The external listener then replaces the 'metasploit-aggregator' project by not requiring an intermediate proxy to park or share sessions, these are done directly by having the listeners independent of console users.

If the independent listener code could be integrated directly into Meterpreter payloads, then local listeners and remote listeners internal to other networks could be implemented the same way.

## Integration with external C2 frameworks

If listeners are externalized, then there is an API layer both for interactive interaction with remote sessions, and a way for the Post-exploitation API to communicate with the external sessions. That should mean that if an external C2 framework supports at minimum shell interaction, a bulk of the Post-exploitation API should be applicable against external C2 frameworks as well. Metasploit would then be able to integrate both with other open-source C2 frameworks, as well as private ones.

## Integration with external exploitation frameworks

E.g. could we just use routersploit or wpsploit directly from within framework and gather loot/run post exploitation, etc. through them? Maybe using the external module RPC, just being able to expose multiple modules behind the same API?

## Native first-class UUID-aware, async stager payload

Make a new async payload type (based on pingback payload work) making secure comms, endpoint verification, and async communication first-class citizens, and on by default. These session types would support a much more limited set of actions than Meterpreter, only supporting sleep/upload/download/stage, but would be upgraded to Meterpreter directly as-needed (maybe even transparently). Network protocols can be much more exotic for this, and the listener/payload should be usable externally from Metasploit as well. Todo: pull in async payload proposal notes from @bwaters-r7.

## Overhaul network targeting

Setting at least 5 variables RHOSTS/RPORT/SSL/VHOST/SSL_Version/User/Pass/etc... to target a single web application is very cumbersome. When these variables also do not apply to multiple RHOSTS exactly, the scheme of multiple variables falls apart futher. Metasploit should be able to target URLs directly, that can all have their own independent ports, users, hostnames, etc:

```
set TARGETS https://user:password@target_app:4343 https://target_app2
```

## Overhaul credential targeting

The credential datastore options also has many different co-dependent and independent variables, which are confusing and awkward to use. In addition, there is little in the way of user-parallelism for using login scanners against single-service web apps. MSF6 should have an easier less messy overhaul of targeting multiple users and apps as well. Maybe TARGETS could be used the same way?

## Temporal / log-oriented data model

Metasploit implements a standard Ruby-on-Rails CRUD model for storing data about an environment. A Host object is created, updated, deleted, etc. But, anything can update anything, making it easy to lose data, and hard to notice changes over time. A workaround is religious use of workspaces to segregate observations, but that's more of a workaround. A log-structured data model (observations about hosts/loot/credentials/services, etc.) should just be objects that are imported into a datastore that prioritizes search over everything else.

As a concrete example, say every `report_*` method just wrote a JSON blob into elasticsearch. Then you would have first observed data, and when something else happens, say a password is cracked, rather than modifying a credential object, there would just be an enrichment object added to the data store, and both could be matched together later. The current data model also often doesn't have ways of storing arbitrary information from modules that need it; loot is often used as a workaround, but it's not searchable by content. Providing a way to store arbitrary JSON from modules would allow the flexibility to store anything, search for anything, and to never lose anything.

Note: a temporal data model will likely need something better able to show data relations than the current tabular rex-table approach in msfconsole. Web UI?

## Collapse module types, expose module 'abilities' or 'methods' instead

Modules in Metasploit are classified according to what they can do ('exploits can exploit, scanners can scan') but often its useful to be able to scan for exploitable targets. Workarounds include reaching between modules and sharing library code and mixins. This proposal suggests that 'exploit' and 'scanner', as well as many other aux-type modules should collapse into a single module type. They simply expose capabilities like 'scan', 'check', 'exploit', etc. and a single module can do all of these.

Additionally, 'admin' modules could be collapsed. For instance, why have a chromecast_reset and chromecast_youtube module when you can use 'admin/chromecast' and just type 'cast' or 'reset' as methods on this single module. This would also replace the 'ACTIONS' datastore option where they are used in multi-action aux modules.

## Make Metasploit Higher-performance / lighter weight

As subcomponents get carved off (external database service, external listeners), they should be implemented in a lighter weight way. We have some prototypes of the database web service rewritten in golang, and a persistent payload generation service that can be used my a client-only `msfvenom`-like tool can speed up execution considerably.

## Sunsetting, separation of old module / code

Metasploit has some really old modules that probably don't get used very often. Can we segregate these or sunset them so that the overall number of modules is reduced?

## Changing module structure on disk

Currently a non-trivial exploit module will require adding code to 4 different subdirectories (lib, modules, documentation, external) which makes it both hard to follow all of the moving pieces, but also makes it harder to extract modules for independent use. See https://github.com/rapid7/metasploit-framework/wiki/Bundled-Modules-Proposal for a more detailed proposal.