# Metasploit's 2017 Roadmap

Starting in 2017, we will provide an open roadmap for setting our goals for the year. The goals are based on many discussions we have had over the past year with users, developers, and customers. The intent is to provide focus for core developers and contributors alike, so that we can together work toward a common vision for how we want Metasploit to evolve.

This year, the themes for Metasploit are modularity, reusability, and reliability.

Metasploit has grown organically over the years into a very large project, combining thousands of modules, payloads, a database, session handling, user interaction and more into a single monolithic application. While the design has served us well, it has reached some limits for maintainability and agility. While we continue to refactor, improve, and reorganize Metasploit, large-scale improvements become increasingly difficult and highlight fragility in the overall system, due to its highly interdependent design.

We want to allow users to effortlessly contribute to the portions of Metasploit they are interested in, and be able to reuse code, both from inside and and outside of the project. Language and licensing constraints have presented barriers to users, both real and imagined. Python, Go, C# and other languages are dominating influences on the infosec community. We would like to be able to welcome more developers, researchers, and tooling into the Metasploit ecosystem, taking advantage of the best-in-breed and avoiding not-invented-here syndrome wherever possible.

In short, we want to develop reusable, modular, and reliable services to enable researchers, pen-testers, students, and red-teamers to work efficiently, have access to the latest technologies and techniques, and to continue to grow the Metasploit community.

## The roadmap

 * The Metasploit data model backend should be separated into its own project. Plans include a data service that provides a RESTful interface, both an event-oriented and classic workspace-oriented view of incoming data, improved performance, and easy direct interoperability with other tools.

 * Session handling should be able to operate independently of framework, allowing users to share sessions and allowing servers to be as performant, reliable, and light-weight as possible. We have already begun a project called 'metasploit-aggregator' which is a first generation of this design. Once this is complete, direct integration into other frameworks should also be possible.

 * Metasploit should support asynchronous sessions. Many testers today use asynchronous frameworks like Empire to maintain light-weight persistence or a footholds into a network, then have to pivot to Meterpreter for interactive sessions. We would like to be able seamlessly support both modes of operation, including the ability to run post exploitation modules and modules over pivots asynchronously as well.

 * Metasploit should support running exploit and auxiliary modules in an isolated mode. Plans are underway to support supporting an RPC-style module API to Metasploit framework, providing core services like payload and session handling, network routing, reporting and logging. Modules are run as child processes to Metasploit, and are only loaded into memory as-needed. Networking from a module point-of-view will be handled via SOCKS5 proxy support, hooking the child environment, or remote API calls, largely removing the need for specially-crafted socket objects or changes to 3rd-party protocol libraries. Modules, when written for the Metasploit API, could even be tested and used independently from the full Metasploit framework.

In addition to these primary goals, we'd also like to explore:

 * *SMB 2.0* SMB 1.0 increasingly being disabled in many networks, making Metasploit modules using this protocol ineffective. We would like to implement at least server-side support for SMB 2.0, both for sharing files and for named pipe communications.
 * *iOS and macOS support* The mettle and python meterpreter payloads will continue evolving to further support OS X and iOS, along with more post exploitation support.
 * *Native Android support in Mettle* We began the work last year with mettle now supporting all of the basic operations for a Meterpreter implementation. We would like to continue adding Android post-exploitation capabilities to mettle as well.
 * *Streamlining Windows Meterpreter* mettle soon will replace the original POSIX meterpreter, which will reduce the size of the Windows meterpreter. Switching from OpenSSL to native SChannel support will simplify and shrink Windows meterpreter, allowing to focus on what it supports best.
 * *Router and IoT research* We would like to continue research and support for embedded device exploitation and first-class support for resource-constrained environments.
 * *Modernizing payload generation* We are investigating being able to integrate with third-party toolchains for building assembly, C, .NET, Java, on the fly, making it easy for a user to acquire the and use the tools, while providing first-class support for many architectures and platforms.