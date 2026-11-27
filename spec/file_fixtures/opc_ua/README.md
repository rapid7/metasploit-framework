# OPC-UA wire captures

Byte-for-byte captures of OPC-UA TCP (`opc.tcp://`) messages, used by the specs
under `spec/lib/rex/proto/opc_ua/`.

Each file is a **complete message including the 8 byte message header**
(MessageType, ChunkType, MessageSize), exactly as it came off the wire. Nothing
has been trimmed, reordered or reassembled. Specs slice what they need; the
fixtures stay whole, so the same file can serve both the transport specs and the
record specs without any question about what was removed.

## Provenance

| | |
|---|---|
| Server | node-opcua 2.175.6 |
| Container | `ua-node` |
| Endpoint | `opc.tcp://ua-node:4840/UA/BackdraftTest` |
| Captured | 2026-08-27 |
| Security policy | None (`http://opcfoundation.org/UA/SecurityPolicy#None`) |
| Framing | Single `F` chunk per message |

| File | Bytes | Contents |
|---|---|---|
| `ack_node_opcua.bin` | 28 | `ACK` response to a Hello |
| `open_secure_channel_response_node_opcua.bin` | 135 | `OPN` response, SecurityPolicy None |
| `get_endpoints_response_node_opcua.bin` | 10648 | `MSG` GetEndpointsResponse, 7 endpoints including a None/Anonymous endpoint |

## Coverage limits

These captures come from one server under one configuration, so several
encodings the parser must handle do not appear in them at all. Specs covering
the following need hand-built frames constructed from OPC-UA Specification
Part 6; that is deliberate, not an oversight:

- **Chunked responses.** Every message here is a single `F` chunk. No capture
  exercises `C`-continuation reassembly or an `A` abort, so the MessageStream
  reassembly specs are hand-built in full.
- **NodeId encodings.** Every NodeId in these captures uses encoding byte `0x01`
  (FourByte). The TwoByte, Numeric, String, GUID and ByteString branches, and
  the `0x40` ServerIndex / `0x80` NamespaceUri flags, have no capture coverage.
- **LocalizedText masks.** Every LocalizedText here has mask `0x03` (both Locale
  and Text present). The `0x00`, `0x01` and `0x02` branches have no capture
  coverage.

## Excluded captures

Equivalent captures from an Inductive Automation Ignition server are
**deliberately excluded and will not be added**. Ignition embeds its server
certificate in the GetEndpoints response, and the certificate's
subjectAltName extension contains the public IP address of the lab host. That
cannot go into a public repository.

The node-opcua captures were checked for the same class of leak before being
committed: they contain no IP addresses, and the only host identifier in them is
the internal container name `ua-node`.
