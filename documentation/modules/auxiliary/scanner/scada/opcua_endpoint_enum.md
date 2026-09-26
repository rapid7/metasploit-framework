## Vulnerable Application

This module enumerates the endpoints advertised by an OPC-UA server over the
OPC-UA TCP binary transport (`opc.tcp://`). OPC-UA (IEC 62541) is the dominant
interoperability standard in industrial automation and is exposed by PLCs, SCADA
platforms, historians, and gateway products.

The module performs the following exchange:

1. **HEL -> ACK** - the OPC-UA connection handshake.
2. **OPN -> OPN** - `OpenSecureChannel` using `SecurityPolicy=None`. No
   cryptography is applied; the asymmetric security header carries the None
   policy URI with null certificate fields.
3. **MSG -> MSG** - the `GetEndpoints` service call.
4. **CLO** - `CloseSecureChannel`, so the channel is released rather than left
   open until its lifetime expires.

`GetEndpoints` is specified as a discovery service that must be reachable
without authentication, so that a client can learn how it is expected to
connect. This holds even when every endpoint the server actually offers demands
encryption and credentials. The module therefore enumerates and reports the
advertised security posture; it does not authenticate, does not browse the
address space, and does not read or write any tags.

For each endpoint the module reports:

* the advertised endpoint URL
* `MessageSecurityMode` (None, Sign, or SignAndEncrypt)
* `SecurityPolicyUri` (None, Basic256Sha256, and so on)
* the accepted `UserIdentityToken` types (Anonymous, UserName, Certificate,
  IssuedToken)

It also reports the server's `ApplicationUri` and `ProductUri`, which fingerprint
the product and distinguish, for example, an Ignition OPC-UA server from Kepware
or a bare open62541 instance.

An endpoint that accepts the **Anonymous** identity token over a channel with
`MessageSecurityMode` **None** is flagged, and a vulnerability is recorded. Such
an endpoint allows any host that can reach the port to connect with no
credentials over an unencrypted channel, which on most deployments is sufficient
to read live process data and, depending on the server's node permissions, to
write it.

### Port Notes

The IANA-registered port for OPC-UA TCP is **4840**, which is this module's
default `RPORT`. Several common OT products use non-standard ports:

* **Inductive Automation Ignition** runs its OPC-UA server on **62541** by
  default. Set `RPORT 62541` when scanning Ignition gateways.
* By default Ignition binds its OPC-UA server to **localhost only**. A
  default-configured gateway is not reachable across the network until an
  administrator adds a non-loopback bind address. See "Setting Up a Test Server"
  below for how to change this on 8.3.x.

### Advertised Endpoint URLs

Servers commonly advertise endpoint URLs that are not reachable from the
scanning host. Ignition, for example, advertises its configured hostname
alongside `localhost` and `127.0.0.1`. These are the server's own view of how it
can be reached, reported verbatim. A client that follows an advertised URL rather
than the address it connected to will fail against those entries.

### Setting Up a Test Server

Any OPC-UA server will exercise the endpoint enumeration path. Two targets are
documented here: an Ignition gateway, which is the primary real-world target,
and a `node-opcua` server, which additionally exercises the weak-endpoint
reporting path.

**Inductive Automation Ignition (Docker)**

```
docker run -d --name ignition-opcua-test \
  -p 8088:8088 -p 62541:62541 \
  -e ACCEPT_IGNITION_EULA=Y \
  -e GATEWAY_ADMIN_USERNAME=admin \
  -e GATEWAY_ADMIN_PASSWORD=password \
  -e IGNITION_EDITION=standard \
  inductiveautomation/ignition:8.3
```

The gateway commissions unattended. The OPC-UA server is enabled by default but
binds to loopback only, so it must be exposed before it is reachable. On 8.3.x
the bind address is a gateway config resource and can be changed over the REST
API with `curl`, with no browser step. The change takes effect immediately; the
OPC-UA module rebinds its endpoints without a gateway restart. The following was
verified against `inductiveautomation/ignition:8.3` (build 8.3.9) and requires
`curl` and `jq`.

```bash
GW=http://localhost:8088
JAR=$(mktemp)

# 1. Authenticate (8.3.x IdP chained-token flow). Walk the login redirects to
#    capture the OIDC auth URL (carries state+nonce) and the IdP token.
url="$GW/data/app/login"; OIDC_URL=""; LOGIN_URL=""
for _ in $(seq 1 12); do
  redirect=$(curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' "$url")
  case "$redirect" in
    */idp/default/oidc/auth\?*)   OIDC_URL="$redirect" ;;
    */idp/default/authn/login\?*) LOGIN_URL="$redirect" ;;
  esac
  [ -z "$redirect" ] && break; url="$redirect"
done
T0=$(printf '%s' "$LOGIN_URL" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p')

T1=$(curl -s -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' \
       -d "{\"token\":\"$T0\"}" "$GW/idp/default/authn/next-challenge" | jq -r .token)
T2=$(curl -s -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' \
       -d "{\"token\":\"$T1\",\"challenge\":{\"username\":\"admin\",\"password\":\"password\"}}" \
       "$GW/idp/default/authn/submit-challenge/basic" | jq -r .token)
T3=$(curl -s -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' \
       -d "{\"token\":\"$T2\"}" "$GW/idp/default/authn/next-challenge" | jq -r .token)
curl -s -b "$JAR" -c "$JAR" -o /dev/null -L "${OIDC_URL}&token=$T3"

# 2. CSRF token (required for the write)
CSRF=$(curl -s -b "$JAR" "$GW/data/app/session" | jq -r .csrfToken)

# 3. Read the OPC-UA server config, set bindAddresses to 0.0.0.0, PUT it back.
#    Note the write path has no "/singleton/" segment and the body is an array.
curl -s -b "$JAR" \
  "$GW/data/api/v1/resources/singleton/com.inductiveautomation.opcua/server-config" \
  | jq '.config.endpoint.bindAddresses = ["0.0.0.0"] | [.]' \
  | curl -s -b "$JAR" -X PUT \
      -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data @- \
      "$GW/data/api/v1/resources/com.inductiveautomation.opcua/server-config"
```

Verify from the gateway log rather than from a host socket listing. With Docker
port publishing the host socket shows `*:62541` whether or not the container
process is bound to loopback, so `ss` cannot distinguish the two states:

```bash
docker logs ignition-opcua-test 2>&1 | grep "Binding endpoint" | tail -6
# ... Binding endpoint opc.tcp://<host>:62541 to 0.0.0.0:62541 [Basic256Sha256/SignAndEncrypt]
```

To revert, repeat step 3 with `["localhost"]`.

The bind address governs which interfaces the server listens on. The endpoint
URLs it advertises come from a separate `endpointAddresses` setting (hostname,
`localhost`, `127.0.0.1`) and are unchanged by the procedure above, which is why
loopback entries still appear in the enumerated list.

**A standalone node-opcua server (Docker)**

Ignition offers no unsecured endpoint, so it cannot exercise the module's
weak-endpoint reporting. `node-opcua` serves its default endpoint set, which
includes `SecurityPolicy=None` with anonymous access alongside the secured
policies. The package version is pinned so that the endpoint set stays
reproducible; a later release that changes the defaults would silently remove
the unsecured endpoint.

`Dockerfile`:

```
FROM node:20-slim
WORKDIR /app
RUN npm install node-opcua@2.175.6
COPY server.js .
EXPOSE 4840
CMD ["node", "server.js"]
```

`server.js`:

```javascript
const { OPCUAServer, Variant, DataType } = require("node-opcua");
(async () => {
  const server = new OPCUAServer({
    port: 4840,
    resourcePath: "/UA/BackdraftTest",
    buildInfo: {
      productName: "BackdraftNodeOpcuaTestServer",
      buildNumber: "1",
      buildDate: new Date()
    }
  });
  await server.initialize();
  const addressSpace = server.engine.addressSpace;
  const namespace = addressSpace.getOwnNamespace();
  const device = namespace.addObject({
    organizedBy: addressSpace.rootFolder.objects,
    browseName: "ProcessValues"
  });
  let level = 42.5;
  namespace.addVariable({
    componentOf: device,
    browseName: "TankLevel",
    dataType: "Double",
    value: {
      get: () => new Variant({ dataType: DataType.Double, value: level })
    }
  });
  namespace.addVariable({
    componentOf: device,
    browseName: "BatchId",
    dataType: "String",
    value: {
      get: () => new Variant({ dataType: DataType.String, value: "LOT-2026-0001" })
    }
  });
  await server.start();
  console.log("[*] node-opcua server listening");
  server.endpoints.forEach((ep) => {
    ep.endpointDescriptions().forEach((desc) => {
      console.log(
        `[*]   ${desc.endpointUrl}  mode=${desc.securityMode}  policy=${desc.securityPolicyUri}`
      );
    });
  });
})();
```

Build and run. The explicit `--hostname` is worth setting: `node-opcua` derives
the advertised endpoint URL from the host name, which inside a container
otherwise defaults to the container ID.

```
docker build -t backdraft/node-opcua .
docker run -d --name ua-node --hostname ua-node -p 4840:4840 backdraft/node-opcua
docker logs ua-node
```

The server prints its own endpoint list at startup, which is a useful
independent check on what the module reports. `mode=1` is None, `mode=2` is
Sign, `mode=3` is SignAndEncrypt:

```
[*] node-opcua server listening
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=1  policy=http://opcfoundation.org/UA/SecurityPolicy#None
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=2  policy=http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=2  policy=http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=2  policy=http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=3  policy=http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=3  policy=http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
[*]   opc.tcp://ua-node:4840/UA/BackdraftTest  mode=3  policy=http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss
```

open62541, Eclipse Milo, and the Prosys Simulation Server are alternatives that
also ship an unsecured endpoint by default.

## Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/scada/opcua_endpoint_enum`
3. `set RHOSTS <target>`
4. If the target is an Ignition gateway, `set RPORT 62541`.
5. `run`
6. Each advertised endpoint is listed with its security policy, security mode,
   and accepted identity token types, followed by the server's `ApplicationUri`
   and `ProductUri`.

## Options

### READ_TIMEOUT

Advanced option. Seconds to wait for each OPC-UA response. Defaults to **5**.
Increase on high-latency links or when a server advertises a large number of
endpoints, each carrying a certificate.

## Scenarios

### Inductive Automation Ignition 8.3.4

A gateway with its OPC-UA server exposed on 62541. All advertised endpoints
require encryption and a username, so nothing is flagged:

```
msf6 > use auxiliary/scanner/scada/opcua_endpoint_enum
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > set RHOSTS 10.10.0.3
RHOSTS => 10.10.0.3
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > set RPORT 62541
RPORT => 62541
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > run

[+] 10.10.0.3:62541       - OPC-UA server enumerated - 3 endpoint(s), 0 unauthenticated and unencrypted
[*] 10.10.0.3:62541       -   [0] opc.tcp://bd-83-primary:62541
[*] 10.10.0.3:62541       -       security: Basic256Sha256/SignAndEncrypt  identity: UserName
[*] 10.10.0.3:62541       -   [1] opc.tcp://localhost:62541
[*] 10.10.0.3:62541       -       security: Basic256Sha256/SignAndEncrypt  identity: UserName
[*] 10.10.0.3:62541       -   [2] opc.tcp://127.0.0.1:62541
[*] 10.10.0.3:62541       -       security: Basic256Sha256/SignAndEncrypt  identity: UserName
[*] 10.10.0.3:62541       -   ApplicationUri: urn:inductiveautomation:ignition:opcua:server:20bd682b-9fa1-4741-9758-341ca9ee66fb
[*] 10.10.0.3:62541       -   ProductUri: urn:inductiveautomation:ignition:opcua:server
[*] 10.10.0.3:62541       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Note that the endpoint list is returned even though no endpoint offers the None
security policy. The discovery channel is open by specification regardless of
what the server's real endpoints require.

### node-opcua 2.175.6, unsecured endpoint present

The `ua-node` container described above, on the default port. Endpoint 0 offers
`SecurityPolicy=None` with `MessageSecurityMode=None` and accepts the Anonymous
identity token, so it is flagged and a vulnerability is recorded:

```
msf6 > use auxiliary/scanner/scada/opcua_endpoint_enum
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > run

[+] 127.0.0.1:4840        - OPC-UA server enumerated - 7 endpoint(s), 1 unauthenticated and unencrypted
[*] 127.0.0.1:4840        -   [0] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: None/None  identity: UserName, Certificate, Anonymous
[!] 127.0.0.1:4840        -       endpoint accepts anonymous clients over an unencrypted channel
[*] 127.0.0.1:4840        -   [1] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Basic256Sha256/Sign  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   [2] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Aes128_Sha256_RsaOaep/Sign  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   [3] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Aes256_Sha256_RsaPss/Sign  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   [4] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Basic256Sha256/SignAndEncrypt  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   [5] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Aes128_Sha256_RsaOaep/SignAndEncrypt  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   [6] opc.tcp://ua-node:4840/UA/BackdraftTest
[*] 127.0.0.1:4840        -       security: Aes256_Sha256_RsaPss/SignAndEncrypt  identity: UserName, Certificate, Anonymous
[*] 127.0.0.1:4840        -   ApplicationUri: urn:ua-node:NodeOPCUA-Server
[*] 127.0.0.1:4840        -   ProductUri: NodeOPCUA-Server
[*] 127.0.0.1:4840        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

All seven endpoints share one URL and differ only in security policy and mode,
which is normal: an OPC-UA server advertises one endpoint per supported
policy/mode combination.

### Server not reachable or not OPC-UA

Hosts that do not answer the Hello are skipped silently unless `VERBOSE` is set:

```
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/scada/opcua_endpoint_enum) > run

[*] 10.10.0.9:4840        - No OPC-UA response to HEL
[*] 10.10.0.9:4840        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

A server that answers the Hello but refuses an unsecured channel is reported as
present, with the reason, and enumeration stops there.

## Confirming Detection

The module records a service of type `opc-ua`, a note of type `opcua.endpoints`
holding the full parsed endpoint list, and a vulnerability entry for any endpoint
accepting anonymous identity without encryption.

```
msf6 > services -S opc-ua
msf6 > notes -t opcua.endpoints
msf6 > vulns
```

## References

* OPC-UA Specification Part 4 (Services) - the GetEndpoints service and the
  EndpointDescription structure, <https://reference.opcfoundation.org/Core/Part4/>
* OPC-UA Specification Part 6 (Mappings) - binary encoding and the OPC-UA
  Connection Protocol, <https://reference.opcfoundation.org/Core/Part6/>
* OPC Foundation - OPC-UA overview,
  <https://opcfoundation.org/about/opc-technologies/opc-ua/>
