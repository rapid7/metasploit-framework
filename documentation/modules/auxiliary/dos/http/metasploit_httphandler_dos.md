## Vulnerable Application

 Metasploit Framework before version 5.0.28

## Verification Steps

  1. Install Metasploit 5.0.27 or earlier (or checkout before commit 5621d200ccf62e4a8f0dad80c1c74f4e0e52d86b)
  2. Start msfconsole with the target Metasploit instance and start any reverse_http/reverse_https listener
  3. Start this module and set RHOSTS and RPORT to the target listener address and port.
  4. Run the modulest <rhost>```
  7. `msfconsole` should use 99%+ CPU for a varying amount of time depending on the DOSTYPE option. You may need to kill the process manually.

## Options

 **DOSTYPE**

	GENTLE: *Current sessions will continue to work, but not future ones*
	  A lack of input sanitation permits an attacker to submit a request that will be added to the resources and will be used as regex rule it is possible then to make a valid regex rule that captures all the new handler requests. The sessions that were established previously will continue to work.

	SOFT: *No past or future sessions will work*
      A lack of input sanitation and lack of exception handling causes Metasploit to behave abnormally when looking an appropriate resource for the request, by submitting an invalid regex as a resource. This means that no request, current or future will get served an answer.

	HARD: *ReDOS or Catastrophic Regex Backtracking*
	  A lack of input sanitization on paths added as resources allows an attacker to execute a catastrophic regex backtracking operation causing a Denial of Service by CPU consumption.

## Scenarios

```
msf5 auxiliary(dos/http/metasploit_httphandler_dos) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:8080 - Sending DoS packet...
^C[-] Stopping running againest current target...
[*] Control-C again to force quit all targets.
[*] Auxiliary module execution completed
```
