There comes a time in the life of many a Meterpreter session when it needs to go quiet for a while. There are many reasons that this might be needed:

* During an assessment, the blue team may have detected suspicious activity, and communications is too noisy.
* Long term engagements require long-term shells, but the red team isn't awake 24-hours a day, and so keeping the communications active the whole time doesn't make sense.
* Users may just want to reduce the number of shells they have to worry about at a given time and want some of them to go away for a while.

For these reasons, and more, the new `sleep` command in Meterpreter was created. This document explains what it is and how it works.

## Silent shells

Noise during an assessment is not necessarily a good thing. With the advent of Meterpreter's new support and control of [[multiple transports|./Meterpreter-Transport-Control.md]], Meterpreter has the ability to change transports and therefore change the traffic pattern for communication. However, sometimes this isn't enough and sometimes users want to be able to shut the session off temporarily.

The `sleep` command is designed to do just that: make the current Meterpreter session go to sleep for a specified period of time, and the wake up again once that time has expired.

During this dormant period, no socket is active, no requests are made, and no responses are given. From the perspective of Metasploit it's as if the Meterpreter session doesn't exist.

The interface to the sleep command looks like this:

```msf
meterpreter > sleep
Usage: sleep <time>

  time: Number of seconds to wait (positive integer)

  This command tells Meterpreter to go to sleep for the specified
  number of seconds. Sleeping will result in the transport being
  shut down and restarted after the designated timeout.
```

As shown, `sleep` expects to be given a single positive integer value that represents the number of seconds that Meterpreter should be silent for. When run, the session will close, and then callback after the elapsed period of time. Given that Meterpreter lives in memory, this lack of communication will make it extremely difficult to track.

The following shows a sample run where Meterpreter is put to sleep for 20 seconds, after which the session reconnects while the handler is still in background:

```msf
meterpreter > sleep 20
[*] Telling the target instance to sleep for 20 seconds ...
[+] Target instance has gone to sleep, terminating current session.

[*] 10.1.10.35 - Meterpreter session 3 closed.  Reason: User exit
msf exploit(handler) > [*] Meterpreter session 4 opened (10.1.10.40:6005 -> 10.1.10.35:49315) at 2015-06-02 23:00:29 +1000

msf exploit(handler) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > getuid
Server username: WIN-S45GUQ5KGVK\OJ
```

## Under the hood

The implementation of this command was made rather simple as a result of the work that was done to support multiple transports. To facilitate this command, all that happens is:

* A transport change is invoked, but the transport that is selected as the "next" transport is the same as the currently active one.
* The transport is shut down and the session is closed.
* The timeout value is passed to a call to `sleep()`, forcing the main thread of execution to pause for the allotted period of time.
* Execution resumes, and the resumption of connectivity continues in the usual transport switching fashion, only in this case, the transport that is fired up is the one that was just shut down.

In short, the `sleep` command is a transport switch to the current transport with a delay. Simple!
