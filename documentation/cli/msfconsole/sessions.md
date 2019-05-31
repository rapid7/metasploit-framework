Sessions
========

The `sessions` command is used to manage or interact with instances of payloads
that are connected to Metasploit. Sessions are created when a payload connects
back to a running handler ("reverse" payloads), or a payload listens on a
host/port where a handler is expecting to connect to it ("bind" payloads).

Different types of payloads create sessions with different capabilities. The
most common types of sessions are `meterpreter` and `shell`. Both kinds
support interaction and running most available `post` modules.
