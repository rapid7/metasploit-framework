The cmd/unix/bind_busybox_telnetd payload provides a bind TCP Unix command shell
via BusyBox telnetd.

## Vulnerable Application

cmd/unix/bind_busybox_telnetd should work on either 32 or 64-bit Linux platforms
with BusyBox telnetd installed.

## Options

  **LOGIN_CMD**

  The command telnetd will execute on connect. The default value is `/bin/sh`
  in order to provide a command shell.

### Advanced

  **CommandShellCleanupCommand**

  The command to run before the session is closed. The default value is
  `pkill telnetd` and is used to avoid leaving a persistent command shell
  that does not require authentication.

## Deploying cmd/unix/bind_busybox_telnetd

To set the payload:

1. In msfconsole, load the exploit.
2. Do: `set PAYLOAD cmd/unix/bind_busybox_telnetd`
3. Do: `exploit`

## Notes

The shell cleanup command should result in the payload automatically
terminating the telnetd service as the session completes. However, intermittent
behavior was observed and the source has not been identified. When closing a
session please verify, via a port scan or other desired method, that the port
is no longer open. If the port remains open, then the unauthenticated telnetd
service is still running. Establish a connection to the unauthenticated telnetd
service and manually terminate the process (`pkill telnetd`) to avoid leaving
the host more insecure.
