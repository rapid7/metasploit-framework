## Vulnerable Application

Opens a serial connection to a Quectel cellular modem and registers it as a 'modem' session capable of network
pivoting. The Quectel modems have a limited number of sockets available, configurable using MODEM_SOCKETS. Once
the session is established, it can be routed through using the `route` command.

The Quectel modems do not support all socket operations that other session types such as Meterpreter support. Notable
limitations include not being able to bind to a particular address for any socket and no TCP server support.

This module requires local serial access to a Quectel modem. It has been tested with a Quectel EG91-NA.

## Verification Steps

1. Make a physical connection to the Quectel modem over an RS232 serial cable (optionally with a USB adapter).
2. Identify the connection, e.g. `/dev/ttyUSB0`.
3. Optionally `chmod` it to make it readable by the Metasploit user which will require read and write access to it.
4. Start msfconsole
5. Load the `request` plugin by running `load request`
6. Use the `request` command to obtain the current, unpivoted IP address by running `request -A curl/ https://ifconfig.me`
7. Do: `use auxiliary/server/quectel_modem`
8. Do: `set SERIAL /dev/ttyUSB0` where `/dev/ttyUSB0` is the previously identified connection.
9. Do: `run`, you should see a session opened
10. Do: `route add 0 0 -1` to route all of the traffic through the session.
11. Repeat the `request` to ifconfig.me step and see a different IP address.

## Options

### MODEM_SOCKETS

Number of Quectel socket IDs (SID pool size). This is effectively the number of concurrent connections the modem
supports. The default is `12`.

### SERIAL

Serial device for the Quectel modem. The default is `/dev/ttyUSB0`.

### BAUD

Serial baud rate. The default is `115200`.

### MAX_CHUNK_SIZE

Bytes per AT+QISEND chunk. The default is `1024`.

### PROMPT_TIMEOUT_MS, ACK_TIMEOUT_MS, OPEN_TIMEOUT_MS, CMD_TIMEOUT_MS

Timeout controls for serial AT command operations.

### STARTUP_OK_TIMEOUT_S, STARTUP_OK_INTERVAL_MS, HEALTHCHECK_INTERVAL_S, HEALTHCHECK_TIMEOUT_MS, HEALTHCHECK_MAX_FAILS

Startup probing and runtime health check controls.

## Scenarios
