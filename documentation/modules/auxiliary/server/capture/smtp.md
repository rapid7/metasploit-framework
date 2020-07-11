## Vulnerable Application

This module creates a mock SMTP server which accepts credentials or unauthenticated email
before throwing a `503` error.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/smtp```
  3. Do: ```run```

## Options

## Scenarios

### Testing Script

The following script should test the following:

1. Auth Plain
2. Auth Login
3. Auth CRAM-MD5
4. Sending an email w/o auth
5. RSET is implemented (https://github.com/rapid7/metasploit-framework/issues/11980)

    ```
    require 'net/smtp'
    require 'socket'

    puts 'Testing: plain'
    begin
      Net::SMTP.start('127.0.0.1', 25, 'localhost', 'username_plain', 'password_plain', :plain)
    rescue => e
      puts "Error: #{e}"
    end
    
    puts 'Testing: login'
    begin
      Net::SMTP.start('127.0.0.1', 25, 'localhost', 'username_login', 'password_login', :login)
    rescue => e
      puts "Error: #{e}"
    end
    
    puts 'Testing: cram md5'
    begin
      Net::SMTP.start('127.0.0.1', 25, 'localhost', 'username_cram', 'password_cram', :cram_md5)
    rescue => e
      puts "Error: #{e}"
    end
    
    puts 'Testing: DATA'
    begin
      Net::SMTP.start('127.0.0.1') do |smtp|
        smtp.send_message 'test', 'from@test.com', 'to@test.com'
      end
    rescue => e
      puts "Error: #{e}"
    end
    
    
    # test for https://github.com/rapid7/metasploit-framework/issues/11980
    puts 'Testing: RSET during DATA'
    begin
      t = TCPSocket.open('127.0.0.1', 25)
      t.gets
      t.print("EHLO localhost \r\n")
      t.gets
      t.print("MAIL FROM:<from@test.com>\r\n")
      t.gets
      t.print("MAIL TO:<to@test.com>\r\n")
      t.gets
      t.print("DATA\r\n")
      t.gets
      t.print("RSET\r\n")
      puts "  Response: #{t.gets.chop}"
    rescue => e
      puts "Error: #{e}"
    end

    puts 'Testing: RSET during middle of DATA'
    begin
      t = TCPSocket.open('127.0.0.1', 25)
      t.gets
      t.print("EHLO localhost \r\n")
      t.gets
      t.print("MAIL FROM:<from@test.com>\r\n")
      t.gets
      t.print("MAIL TO:<to@test.com>\r\n")
      t.gets
      t.print("DATA\r\n")
      t.gets
      t.print("testing a message which gets cancelled\r\n")
      t.print("RSET\r\n")
      puts "  Response: #{t.gets.chop}"
    rescue => e
      puts "Error: #{e}"
    end
    ```

### Output from testing script

When this script is run from the Metasploit console, it intermingles with the commands, which is great!

```
$ sudo ./msfconsole -qx 'use auxiliary/server/capture/smtp; set srvhost 127.0.0.1;run;ruby tools/dev/test_capture_smtp.rb'
srvhost => 127.0.0.1
[*] Auxiliary module running as background job 0.
[*] exec: ruby tools/dev/test_capture_smtp.rb

[*] Started service listener on 127.0.0.1:25 
[*] Server started.
Testing: plain
[*] SMTP: 127.0.0.1:46212 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46212 Command: AUTH PLAIN AHVzZXJuYW1lX3BsYWluAHBhc3N3b3JkX3BsYWlu
[+] SMTP LOGIN 127.0.0.1:46212 username_plain / password_plain
Testing: login
[*] SMTP: 127.0.0.1:46214 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46214 Command: AUTH LOGIN
[*] SMTP: 127.0.0.1:46214 Command: dXNlcm5hbWVfbG9naW4=
[*] SMTP: 127.0.0.1:46214 Command: cGFzc3dvcmRfbG9naW4=
[+] SMTP LOGIN 127.0.0.1:46214 username_login / password_login
Testing: cram md5
[*] SMTP: 127.0.0.1:46216 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46216 Command: AUTH CRAM-MD5
[*] SMTP: 127.0.0.1:46216 Command: dXNlcm5hbWVfY3JhbSA3YjA2NzUyMjVhM2FjMmI5MjMxYzJlOTM5OTg2Y2U0Mg==
Testing: DATA
[+] SMTP LOGIN 127.0.0.1:46216 username_cram / <12345@127.0.0.1>#7b0675225a3ac2b9231c2e939986ce42
[*] SMTP: 127.0.0.1:46218 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46218 Command: MAIL FROM:<from@test.com>
[*] SMTP: 127.0.0.1:46218 Command: RCPT TO:<to@test.com>
[*] SMTP: 127.0.0.1:46218 Command: DATA
[*] SMTP: 127.0.0.1:46218 Command: test
.
[*] SMTP: 127.0.0.1:46218 EMAIL: test
[*] SMTP: 127.0.0.1:46218 Command: QUIT
Testing: RSET during DATA
[*] SMTP: 127.0.0.1:46220 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46220 Command: MAIL FROM:<from@test.com>
[*] SMTP: 127.0.0.1:46220 Command: MAIL TO:<to@test.com>
[*] SMTP: 127.0.0.1:46220 Command: DATA
[*] SMTP: 127.0.0.1:46220 Command: RSET
  Response: 250 OK
Testing: RSET during middle of DATA
[*] SMTP: 127.0.0.1:46222 Command: EHLO localhost
[*] SMTP: 127.0.0.1:46222 Command: MAIL FROM:<from@test.com>
[*] SMTP: 127.0.0.1:46222 Command: MAIL TO:<to@test.com>
[*] SMTP: 127.0.0.1:46222 Command: DATA
[*] SMTP: 127.0.0.1:46222 Command: testing a message which gets cancelled
RSET
[*] SMTP: 127.0.0.1:46222 EMAIL: testing a message which gets cancelled
  Response: 250 OK
msf5 auxiliary(server/capture/smtp) > creds
Credentials
===========

host       origin     service        public          private                                             realm  private_type        JtR Format
----       ------     -------        ------          -------                                             -----  ------------        ----------
127.0.0.1  127.0.0.1  25/tcp (smtp)  username_cram   <12345@127.0.0.1>#7b0675225a3ac2b9231c2e939986ce42         Nonreplayable hash  hmac-md5
127.0.0.1  127.0.0.1  25/tcp (smtp)  username_login  password_login                                             Password            
127.0.0.1  127.0.0.1  25/tcp (smtp)  username_plain  password_plain                                             Password            

msf5 auxiliary(server/capture/smtp) > notes

Notes
=====

 Time                     Host       Service  Port  Protocol  Type          Data
 ----                     ----       -------  ----  --------  ----          ----
 2020-04-17 15:11:24 UTC  127.0.0.1                           smtp_message  "testing a message which gets cancelled\r\n"


```

### Cracking Cram-md5 (hmac-md5)

Metasploit currently doesn't have a cracker for `hmac-md5`, however the output is pre-formatted to JTR standards,
and `creds -o /tmp/file.jtr` will export it correctly for John.  It is also possible to export to hashcat format
with `creds -o /tmp/file.hcat` and mode `10200`.

```
user@kali:~/metasploit-framework$ sudo cat /tmp/cram
username_cram:<12345@127.0.0.1>#7b0675225a3ac2b9231c2e939986ce42
user@kali:~/metasploit-framework$ sudo cat /tmp/wordlist 
password_cram
user@kali:~/metasploit-framework$ sudo john --wordlist=/tmp/wordlist --format=hmac-md5 /tmp/cram
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-MD5 [password is key, MD5 256/256 AVX2 8x3])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 192 needed for performance.
password_cram    (username_cram)
1g 0:00:00:00 DONE (2020-04-17 11:32) 50.00g/s 50.00p/s 50.00c/s 50.00C/s password_cram
Use the "--show --format=HMAC-MD5" options to display all of the cracked passwords reliably
Session completed
```
