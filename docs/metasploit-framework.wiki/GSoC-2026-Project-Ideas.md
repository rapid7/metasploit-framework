GSoC Project Ideas in no particular order. When you've picked one, take a look at [[How-to-Apply-to-GSoC]] for how to make a proposal.

Mentors: [@jheysel-r7](https://github.com/jheysel-r7)
Co-mentors: [@zeroSteiner](https://github.com/zeroSteiner) [@h00die](https://github.com/h00die)

Slack Contacts: @jheysel, @zeroSteiner and @h00die on [Metasploit Slack](https://metasploit.slack.com/)


For any questions about these projects reach out on the Metasploit Slack in the `#gsoc` channel or DM one of the mentors
using the Slack contacts listed above. Note that mentors may be busy so please don't expect an immediate response,
however we will endeavor to respond as soon as possible. If you'd prefer not to join Slack, you can also email
`msfdev [@] metasploit [dot] com` and we will respond to your questions there if email is preferable.

## Enhance Metasploit Framework
### CertificateTrace and KerberosTicketTrace Support

Kerberos and certificate-based authentication mechanisms are becoming increasingly prevalent across modern environments,
particularly in Active Directory and enterprise deployments. As a result, Metasploit modules that interact with these
authentication flows often require operators and developers to inspect Kerberos tickets or certificate material in order
to understand behavior, troubleshoot failures, or validate exploitation techniques. Today, this inspection typically
requires switching to separate auxiliary modules or exporting artifacts (such as .pfx files) for analysis with external
tooling, which interrupts the normal workflow.

This project would introduce CertificateTrace and KerberosTicketTrace functionality to Metasploit, allowing relevant
authentication artifacts to be captured and inspected as part of module execution. Similar in concept to the existing
HttpTrace capability, these traces would focus specifically on certificate and Kerberos-based authentication, decoding
and presenting useful metadata in a consistent, operator-friendly format. Similar to HttpTrace and HttpTraceHeadersOnly,
we would expect there to be support for different levels of logging, ex: print only the Certificate Signing Request (CSR).


Mentors: @jheysel-r7, @zeroSteiner

Size: 175 hrs

Difficulty: Medium

Required Skills: Understanding of how Kerberos and certificate-based authentication work; ability to write and deliver Ruby code.

Preferred Skills: Experience working with or using Kerberos and/or certificate-based authentication.


### Automated Vulnerable Environment Provisioning (build_vuln)

Many Metasploit modules—particularly those targeting web applications or open source software—include documentation
describing how to build a vulnerable test environment, and some provide vulnerable container images to simplify this
process. However, this information is typically maintained in module documentation and requires users to manually build
and start the environment outside of Metasploit, making module verification more time-consuming and inconsistent.

This project proposes a new Metasploit command (for example, build_vuln) that automates launching a vulnerable
environment for a given exploit module. Vulnerable environments would be defined using Open Container Initiative
(OCI)–compliant configurations and designed to work with both Podman and Docker, with rootless execution.

The goal of this project is to automate setup steps that are already documented today, making it easier for users to
test exploits locally and for contributors and Rapid7 engineers to verify module behavior in a repeatable,
well-defined environment. This project would include refactoring existing modules to leverage the new functionality
where possible (docker-compose files already exist), as well as creating new vulnerable environment definitions for
popular modules that lack them today.


Mentors: @jheysel-r7, @h00die

Size: 360 hrs

Difficulty: Medium

Required Skills: Understanding of how containers work in the context of the Open Container Initiative; ability to write and deliver Ruby code.

Preferred Skills: Experience using containers; understanding of container definitions and best practices.


## Submit your own

If you want to suggest your own idea, please discuss it with us first on [Slack](https://metasploit.com/slack) in the
`#gsoc` channel to make sure it is a reasonable amount of work for a summer and that it fits the goals of the project.
