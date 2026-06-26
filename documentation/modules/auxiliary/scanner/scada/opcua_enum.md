## Vulnerable Application

This module detects OPC-UA servers that speak the OPC-UA TCP binary transport
(`opc.tcp://`). OPC-UA (IEC 62541) is the dominant interoperability standard for
industrial automation and is exposed by a wide range of OT software, including
PLCs, SCADA platforms, historians, and gateway products.

The module sends an OPC-UA **Hello (HEL)** message and inspects the response:

* An **Acknowledge (ACK)** message confirms the server accepted the connection.
  The server's advertised ProtocolVersion and buffer sizes are reported.
* An **Error (ERR)** message also confirms an OPC-UA server is present; the
  returned StatusCode and reason string are decoded and reported.

Any response other than ACK or ERR is treated as a non-detection, keeping the
fingerprint tight and avoiding false positives from unrelated services.

### Port Notes

The IANA-registered port for OPC-UA TCP is **4840**, which is the module's
default `RPORT`. However, several common OT products use non-standard ports:

* **Inductive Automation Ignition** runs its OPC-UA server on **62541** by
  default, not 4840. When scanning Ignition gateways, set `RPORT 62541`.
* By default, Ignition's OPC-UA server binds to **localhost only**. A
  default-configured gateway will therefore not be reachable across the network
  until an administrator adds a non-loopback bind address (e.g. `0.0.0.0`) in
  Config > OPC UA > Server Settings. In practice this means many Ignition
  installs do not expose OPC-UA externally unless deliberately configured to.

### Setting Up a Test Server (Ignition)

1. Install Inductive Automation Ignition (8.x or 8.3.x). The OPC-UA server is
   enabled by default and listens on TCP **62541**.
2. To make the server reachable across the network, browse to the gateway web
   UI (default `http://<gateway>:8088`), go to **Config > OPC UA > Server
   Settings**, and under **Bind Addresses** remove `localhost` and add `0.0.0.0`
   (or the specific interface IP). Save. The server rebinds without a gateway
   restart.
3. Confirm the listener is bound off-loopback:

   ```
   ss -tlnp | grep 62541
   LISTEN 0 4096 *:62541 *:* users:(("java",...))
   ```

Alternatively, any standalone OPC-UA server (open62541, Eclipse Milo,
Prosys Simulation Server, etc.) on port 4840 can be used to exercise the module.

## Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/scada/opcua_enum`
3. `set RHOSTS <target>`
4. If the target is an Ignition gateway, `set RPORT 62541`.
5. `run`
6. A detected OPC-UA server is reported with `[+]`, including the ProtocolVersion
   and the server's advertised receive/send buffer sizes.

## Options

### RPORT

The target port for the OPC-UA TCP binary transport. Defaults to **4840** (the
IANA-registered OPC-UA port). Set to **62541** when targeting Inductive
Automation Ignition gateways.

## Scenarios

### Inductive Automation Ignition 8.3.4 (OPC-UA server on 62541)

```
msf6 > use auxiliary/scanner/scada/opcua_enum
msf6 auxiliary(scanner/scada/opcua_enum) > set RHOSTS 10.10.0.3
RHOSTS => 10.10.0.3
msf6 auxiliary(scanner/scada/opcua_enum) > set RPORT 62541
RPORT => 62541
msf6 auxiliary(scanner/scada/opcua_enum) > run

[+] 10.10.0.3:62541 - OPC-UA server detected (ACK) - ProtocolVersion=0 RecvBuf=65535 SendBuf=65535
[*] 10.10.0.3:62541 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Server returning an Error response

A server that rejects the HEL (for example, due to an invalid endpoint URL) still
confirms OPC-UA. The StatusCode and reason are decoded:

```
msf6 auxiliary(scanner/scada/opcua_enum) > run

[+] 192.0.2.10:4840 - OPC-UA server detected (ERR) - Bad_TcpEndpointUrlInvalid
[*] 192.0.2.10:4840 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a range

```
msf6 auxiliary(scanner/scada/opcua_enum) > set RHOSTS 10.10.0.0/24
RHOSTS => 10.10.0.0/24
msf6 auxiliary(scanner/scada/opcua_enum) > run

[+] 10.10.0.3:4840 - OPC-UA server detected (ACK) - ProtocolVersion=0 RecvBuf=65535 SendBuf=65535
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming Detection

The module reports a service of type `opc-ua` in the database for each detected
server. Review with:

```
msf6 > services -S opc-ua
```

## References

* OPC-UA Specification Part 6 (Mappings) — OPC-UA Connection Protocol message
  framing (HEL / ACK / ERR), <https://reference.opcfoundation.org/Core/Part6/>
* OPC Foundation — OPC-UA overview,
  <https://opcfoundation.org/about/opc-technologies/opc-ua/>
