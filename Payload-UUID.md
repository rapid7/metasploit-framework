In mid-2015, a new feature was added to many HTTP and TCP Metasploit payloads: Payload UUIDs. A Payload UUID is a 16-byte value that encodes an 8-byte identifier, a 1-byte architecture ID, a 1-byte platform ID, a 4-byte timestamp, and two additional bytes for obfuscation. The [source code comments](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/uuid.rb) go into more detail.

In the case of HTTP payloads, the 16-byte UUID value is encoded in [base64url](https://tools.ietf.org/html/rfc4648#section-5) format resulting in a 22-byte string. This value is always placed in the beginning of the URL used by the payload. TCP payloads send the 16-byte raw value over the socket once a connection is established.

The goal of Payload UUIDs is three-fold:
 * Uniquely identify a generated payload. This is important when running social engineering campaigns to identify what specific payload a target executed. If an email campaign resulted in one user forwarding a payload to another user before it was executed, this can be determined by reviewing the UUID in the session listing.
 * Drop connections that do not match known UUIDs. This allows a listener to be setup that only allows known sessions to connect, which is important when running internet-facing payload handlers.
 * Enable universal handlers. The embedded platform and architecture identifiers allow the listener to determine what type of stage to send back to a stager. This will eventually allow for a single listener to be used with multiple exploits, even those that target different platforms and architectures.



