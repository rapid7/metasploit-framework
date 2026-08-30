## Vulnerable Application

This module creates a mock POP3 server which accepts credentials.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/pop3```
  3. Do: ```run```

## Options

## Scenarios

### Testing Script

The following script will attempt a login of the server.

```
require 'net/pop'

puts 'Attempting Login'
Net::POP3.start('127.0.0.1', 110, 'username', 'password') do |pop|
  # check for email, should be none
  if pop.mails.empty?
    puts 'No mail'
  end
end
```

### Output from testing script

When this script is run from the Metasploit console, it intermingles with the commands.

```
$ sudo ./msfconsole -qx 'use auxiliary/server/capture/pop3; set srvhost 127.0.0.1; run; ruby test_capture_pop3.rb;creds'
srvhost => 127.0.0.1
[*] Auxiliary module running as background job 0.
[*] exec: ruby test_capture_pop3.rb

[*] Started service listener on 127.0.0.1:110 
[*] Server started.
Attempting Login
[+] POP3 LOGIN 127.0.0.1:35766 username / password
No mail
Credentials
===========

host       origin     service         public    private   realm  private_type  JtR Format
----       ------     -------         ------    -------   -----  ------------  ----------
127.0.0.1  127.0.0.1  110/tcp (pop3)  username  password         Password      

```
