Of the many recent changes to Meterpreter, reliable network communication is one of the more welcomed ones. For a long time, Meterpreter's communication with Metasploit has been relatively easy to break. Once broken, the session was officially dead, and the only way to get a session back was to replay the original exploitation path and establish a whole new session.

In the case of HTTP/S transports, some resiliency features were present. Thanks to its stateless nature, HTTP/S transports would continue to attempt to talk to Metasploit after network outages or other unexpected problems as each command request/response is transmitted over a fresh connection. TCP based transports had nothing that would attempt to reconnect should some kind of network issue occur.

Revamped [[transport|./Meterpreter-Transport-Control.md]] implementations have provided support for resiliency even for TCP based communications. Any session that isn't properly terminated by Metasploit will continue to function behind the scenes while Meterpreter attempts to re-establish communications with Metasploit.

It is also possible to control the behaviour of this functionality a little via the use of the various timeout values that can be specified when adding transports to the session, and also on the fly for the current transport. For full details, please see the [[timeout documentation|./Meterpreter-Timeout-Control.md]] for details on those timeout values.

Behind the scenes, Meterpreter now maintains a circular linked list of transports in memory while running. When a transport fails, Meterpreter will shut down and clean up the current transport mechanism resources, and will move onto the next one in the list. From there, Meterpreter will use this transport configuration to attempt to reconnect to Metasploit. It will continue to make these attempts until one of the following occurs:

* The overall session timeout value is reached, at which point the session is terminated.
* The `Retry Total` time for the transport is reached, at which point Meterpreter will move on to the next transport.
* The connection attempt is successful, and communications is re-established with Metasploit.

If Meterpreter has a single transport configured, then it will continue to retry on that single transport repeatedly until the session timeout is reached, or a session is successfully created.

## Important note about resilient transports

Now that both `TCP` and `HTTP/S` payloads contain resiliency features, it's important to know that exiting Metasploit using `exit -y` no longer terminates `TCP` sessions like it used to. If Metasploit is closed using `exit -y` without terminating existing sessions, both `TCP` and `HTTP/S` Meterpreter sessions will continue to run behind the scenes, attempting to connect back to Metasploit on the specified transports. If your intention is to exit Metasploit _and_ terminate all of your sessions, then make sure you run `sessions -K` first.
