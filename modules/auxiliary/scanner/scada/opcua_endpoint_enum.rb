# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Every OPC-UA TCP message begins with an 8 byte header:
  #   MessageType (3 bytes ASCII) + ChunkType (1 byte ASCII) + MessageSize (UInt32 LE)
  # MessageSize is the total length including the header itself.
  HEADER_LEN = 8

  # Each MSG chunk repeats SecureChannelId + TokenId + SequenceNumber + RequestId
  # ahead of its slice of the service payload.
  SECURE_MSG_PREFIX_LEN = 16

  NONE_POLICY_URI = 'http://opcfoundation.org/UA/SecurityPolicy#None'

  # NodeIds for the services used here, in FourByte encoding:
  #   0x01 (FourByte) + NamespaceIndex (Byte) + Identifier (UInt16 LE)
  # Numeric identifiers are from OPC-UA Specification Part 6, Annex A.
  OPN_REQUEST_NODEID = [0x01, 0x00, 446].pack('CCv').freeze
  GET_ENDPOINTS_NODEID = [0x01, 0x00, 428].pack('CCv').freeze
  CLOSE_CHANNEL_NODEID = [0x01, 0x00, 452].pack('CCv').freeze

  # MessageSecurityMode enumeration (Part 4, section 7.15).
  SECURITY_MODES = {
    0 => 'Invalid',
    1 => 'None',
    2 => 'Sign',
    3 => 'SignAndEncrypt'
  }.freeze

  # UserTokenType enumeration (Part 4, section 7.36).
  TOKEN_TYPES = {
    0 => 'Anonymous',
    1 => 'UserName',
    2 => 'Certificate',
    3 => 'IssuedToken'
  }.freeze

  # OPC-UA StatusCodes that may appear in an ERR response from the UA TCP
  # transport. Values per the OPC Foundation StatusCodes definitions
  # (Opc.Ua.StatusCodes) and OPC-UA Specification Part 6.
  STATUS_CODES = {
    # UA TCP transport-specific errors (Part 6, 7.1.2)
    0x807D0000 => 'Bad_TcpServerTooBusy',
    0x807E0000 => 'Bad_TcpMessageTypeInvalid',
    0x807F0000 => 'Bad_TcpSecureChannelUnknown',
    0x80800000 => 'Bad_TcpMessageTooLarge',
    0x80810000 => 'Bad_TcpNotEnoughResources',
    0x80820000 => 'Bad_TcpInternalError',
    0x80830000 => 'Bad_TcpEndpointUrlInvalid',
    # Connection/security errors also seen at the transport layer
    0x80BE0000 => 'Bad_ProtocolVersionUnsupported',
    0x80130000 => 'Bad_SecurityChecksFailed',
    0x80120000 => 'Bad_CertificateInvalid',
    0x80840000 => 'Bad_RequestInterrupted',
    0x80850000 => 'Bad_RequestTimeout',
    0x80860000 => 'Bad_SecureChannelClosed',
    0x80870000 => 'Bad_SecureChannelTokenUnknown',
    0x80AC0000 => 'Bad_ConnectionRejected',
    0x80AE0000 => 'Bad_ConnectionClosed'
  }.freeze

  # Defensive ceilings. A malformed or hostile response must fail quickly rather
  # than allocate without bound or spin on an absurd array length.
  MAX_MESSAGE_SIZE = 4 * 1024 * 1024
  MAX_CHUNKS = 64
  MAX_ENDPOINTS = 64
  MAX_ARRAY_LENGTH = 512

  # Raised whenever a decode would read past the end of a response buffer or
  # encounter an encoding this module does not handle. Always caught locally.
  class UaParseError < StandardError; end

  # Position tracking reader over an OPC-UA binary message body.
  # Encoding rules follow OPC-UA Specification Part 6, section 5.2. All
  # multi-byte integers are little-endian. Every reader advances the cursor and
  # bounds-checks first, so a truncated response raises instead of silently
  # desynchronising the walk through the nested structures.
  class Cursor
    def initialize(data)
      @data = data.to_s.dup.force_encoding('BINARY')
      @pos = 0
    end

    def remaining
      @data.bytesize - @pos
    end

    def take(len)
      raise UaParseError, "read of #{len} bytes past end of buffer" if len.negative? || len > remaining

      out = @data.byteslice(@pos, len)
      @pos += len
      out
    end

    def u8
      take(1).unpack1('C')
    end

    def u16
      take(2).unpack1('v')
    end

    def u32
      take(4).unpack1('V')
    end

    def i32
      take(4).unpack1('l<')
    end

    def i64
      take(8).unpack1('q<')
    end

    def skip(len)
      take(len)
      nil
    end

    # String and ByteString share a wire format: an Int32 length prefix followed
    # by that many bytes. A negative length denotes null; zero denotes empty.
    def bytestring
      len = i32
      return nil if len.negative?

      take(len)
    end

    def string
      raw = bytestring
      return nil if raw.nil?

      raw.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
    end

    def skip_string
      bytestring
      nil
    end

    # Array length prefix. A negative value denotes a null array. Anything above
    # the ceiling is treated as a malformed response.
    def array_length(max = MAX_ARRAY_LENGTH)
      len = i32
      return 0 if len.negative?
      raise UaParseError, "array length #{len} exceeds ceiling #{max}" if len > max

      len
    end

    # LocalizedText: one encoding mask byte, then Locale and/or Text depending
    # on mask bits 0x01 and 0x02. Returns the Text field only.
    def localized_text
      mask = u8
      skip_string if (mask & 0x01).positive?
      (mask & 0x02).positive? ? string : nil
    end

    # NodeId. The low nibble of the leading byte selects the identifier form;
    # bits 0x40 and 0x80 add trailing NamespaceUri and ServerIndex fields.
    def skip_node_id
      encoding = u8
      case encoding & 0x0F
      when 0x00 then skip(1)         # TwoByte: Identifier only
      when 0x01 then skip(3)         # FourByte: ns (Byte) + id (UInt16)
      when 0x02 then skip(6)         # Numeric: ns (UInt16) + id (UInt32)
      when 0x03                      # String: ns (UInt16) + String
        skip(2)
        skip_string
      when 0x04 then skip(2 + 16)    # GUID: ns (UInt16) + 16 bytes
      when 0x05                      # ByteString: ns (UInt16) + ByteString
        skip(2)
        skip_string
      else
        raise UaParseError, format('unknown NodeId encoding 0x%02X', encoding)
      end
      skip_string if (encoding & 0x80).positive?    # NamespaceUri (String), per Part 6 5.2.2.9
      skip(4) if (encoding & 0x40).positive?        # ServerIndex (UInt32), per Part 6 5.2.2.9
      nil
    end

    # ExtensionObject: TypeId NodeId, an encoding byte, then an optional body.
    def skip_extension_object
      skip_node_id
      encoding = u8
      case encoding
      when 0x00 then nil                  # no body
      when 0x01, 0x02 then skip_string    # ByteString or XmlElement body
      else
        raise UaParseError, format('unknown ExtensionObject encoding 0x%02X', encoding)
      end
      nil
    end
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OPC-UA Endpoint Enumeration',
        'Description' => %q{
          This module enumerates the endpoints advertised by an OPC-UA server
          over the OPC-UA TCP binary transport (opc.tcp://). It performs the
          connection handshake, opens a secure channel with SecurityPolicy=None,
          and calls the GetEndpoints service, which the specification requires to
          be available without authentication so that clients can discover how to
          connect.

          For each returned endpoint the module reports the advertised URL, the
          MessageSecurityMode, the SecurityPolicy, and the accepted user identity
          token types, along with the server's ApplicationUri and ProductUri as a
          fingerprint. Endpoints that accept anonymous identity over an
          unencrypted channel are flagged, as these allow an unauthenticated
          client to read and potentially write process data.

          No credentials are used and no address space operations are performed.
        },
        'Author' => [
          'Ethan Thomason <ethan@ethomason.com>'
        ],
        'References' => [
          ['URL', 'https://reference.opcfoundation.org/Core/Part4/'],
          ['URL', 'https://reference.opcfoundation.org/Core/Part6/'],
          ['URL', 'https://opcfoundation.org/about/opc-technologies/opc-ua/']
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 4840
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_advanced_options(
      [
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait for each OPC-UA response', 5])
      ]
    )
  end

  def read_timeout
    datastore['READ_TIMEOUT'].to_i
  end

  # ---------------------------------------------------------------------------
  # Encoding helpers
  # ---------------------------------------------------------------------------

  # Encode a String or ByteString: Int32 length prefix then the raw bytes.
  # A nil value is encoded as null (length -1).
  def encode_string(str)
    return [-1].pack('l<') if str.nil?

    raw = str.to_s.dup.force_encoding('BINARY')
    [raw.bytesize].pack('l<') + raw
  end

  def frame(msg_type, body, chunk = 'F')
    size = HEADER_LEN + body.bytesize
    (msg_type + chunk).b + [size].pack('V') + body
  end

  # RequestHeader (Part 4, section 7.28). The authentication token is a null
  # NodeId because GetEndpoints is called without a session.
  def build_request_header(request_handle)
    hdr = [0x00, 0x00].pack('CC')           # AuthenticationToken: null NodeId
    hdr << [ua_timestamp].pack('q<')        # Timestamp
    hdr << [request_handle].pack('V')       # RequestHandle
    hdr << [0].pack('V')                    # ReturnDiagnostics: none
    hdr << encode_string(nil)               # AuditEntryId: null
    hdr << [10_000].pack('V')               # TimeoutHint in milliseconds
    hdr << [0x00, 0x00, 0x00].pack('CCC')   # AdditionalHeader: null ExtensionObject
    hdr
  end

  # OPC-UA DateTime: 100 nanosecond ticks since 1601-01-01 UTC.
  def ua_timestamp
    ((::Time.now.to_f + 11_644_473_600) * 10_000_000).to_i
  end

  def build_hello(endpoint_url)
    body = [
      0,       # ProtocolVersion
      65_535,  # ReceiveBufferSize
      65_535,  # SendBufferSize
      0,       # MaxMessageSize (0 = no limit)
      0        # MaxChunkCount  (0 = no limit)
    ].pack('V*')
    body << encode_string(endpoint_url)
    frame('HEL', body)
  end

  # OpenSecureChannel for SecurityPolicy=None. The asymmetric security header
  # carries the None policy URI with null certificate fields, so no cryptography
  # is applied to this or any subsequent message on the channel.
  def build_open_secure_channel
    req = OPN_REQUEST_NODEID.dup
    req << build_request_header(1)
    req << [0].pack('V')          # ClientProtocolVersion
    req << [0].pack('V')          # SecurityTokenRequestType: Issue
    req << [1].pack('V')          # MessageSecurityMode: None
    req << encode_string(nil)     # ClientNonce: null under the None policy
    req << [3_600_000].pack('V')  # RequestedLifetime in milliseconds

    asym = encode_string(NONE_POLICY_URI)  # SecurityPolicyUri
    asym << encode_string(nil)             # SenderCertificate
    asym << encode_string(nil)             # ReceiverCertificateThumbprint

    seq = [1, 1].pack('VV')                # SequenceNumber, RequestId

    frame('OPN', [0].pack('V') + asym + seq + req)
  end

  def build_get_endpoints(channel_id, token_id, endpoint_url)
    req = GET_ENDPOINTS_NODEID.dup
    req << build_request_header(2)
    req << encode_string(endpoint_url)  # EndpointUrl
    req << [-1].pack('l<')              # LocaleIds: null array
    req << [-1].pack('l<')              # ProfileUris: null array

    frame('MSG', [channel_id, token_id, 2, 2].pack('VVVV') + req)
  end

  def build_close_secure_channel(channel_id, token_id)
    req = CLOSE_CHANNEL_NODEID.dup
    req << build_request_header(3)

    frame('CLO', [channel_id, token_id, 3, 3].pack('VVVV') + req)
  end

  # ---------------------------------------------------------------------------
  # Transport
  # ---------------------------------------------------------------------------

  # Read exactly len bytes, accumulating across reads. A single read is not
  # guaranteed to return the full amount and a GetEndpoints response carrying
  # server certificates routinely spans several segments.
  def read_exact(len)
    buf = ''.b
    deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + read_timeout
    while buf.bytesize < len
      left = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
      return nil unless left.positive?

      chunk = sock.get_once(len - buf.bytesize, left)
      return nil if chunk.nil? || chunk.empty?

      buf << chunk.b
    end
    buf
  end

  # Read one framed message. Returns [message_type, chunk_type, body] or nil.
  def recv_message
    header = read_exact(HEADER_LEN)
    return nil if header.nil?

    size = header.byteslice(4, 4).unpack1('V')
    return nil if size < HEADER_LEN || size > MAX_MESSAGE_SIZE

    body_len = size - HEADER_LEN
    body = body_len.positive? ? read_exact(body_len) : ''.b
    return nil if body.nil?

    [header.byteslice(0, 3), header.byteslice(3, 1), body]
  end

  # Read a complete service response, reassembling chunks where the server has
  # split it. Continuation chunks repeat the SecureChannelId, TokenId and
  # SequenceHeader ahead of their payload slice, so those bytes are stripped
  # before concatenation. The returned buffer therefore starts at the response
  # TypeId, not at the SecureChannelId.
  # Returns [payload, nil] on success or [nil, reason] on failure.
  def recv_service_response
    payload = ''.b
    MAX_CHUNKS.times do
      msg = recv_message
      return [nil, 'no response'] if msg.nil?

      msg_type, chunk_type, body = msg

      if msg_type == 'ERR'
        status, reason = decode_error(body)
        detail = reason.to_s.empty? ? status : "#{status} - #{reason}"
        return [nil, "server returned ERR: #{detail}"]
      end
      return [nil, "unexpected message type #{msg_type.inspect}"] unless msg_type == 'MSG'
      return [nil, 'server aborted the response'] if chunk_type == 'A'
      return [nil, 'chunk shorter than its own headers'] if body.bytesize < SECURE_MSG_PREFIX_LEN

      payload << body.byteslice(SECURE_MSG_PREFIX_LEN..-1).to_s
      return [payload, nil] if chunk_type == 'F'
    end
    [nil, "response exceeded #{MAX_CHUNKS} chunks"]
  end

  # Decode an ERR body: UInt32 StatusCode followed by a String reason.
  def decode_error(body)
    return ['unknown', ''] if body.bytesize < 4

    code = body.byteslice(0, 4).unpack1('V')
    status = STATUS_CODES[code] || format('0x%08X', code)

    reason = ''
    if body.bytesize >= 8
      reason_len = body.byteslice(4, 4).unpack1('V')
      if reason_len != 0xFFFFFFFF && reason_len.positive? && body.bytesize >= 8 + reason_len
        reason = body.byteslice(8, reason_len).to_s
      end
    end

    [status, reason]
  end

  # ---------------------------------------------------------------------------
  # Response parsing
  # ---------------------------------------------------------------------------

  # ResponseHeader (Part 4, section 7.29). Returns the ServiceResult.
  def parse_response_header(cur)
    cur.skip(8)                       # Timestamp
    cur.skip(4)                       # RequestHandle
    service_result = cur.u32
    diagnostics_mask = cur.u8         # ServiceDiagnostics encoding mask
    raise UaParseError, 'diagnostic info present but not requested' unless diagnostics_mask.zero?

    cur.array_length.times { cur.skip_string }  # StringTable
    cur.skip_extension_object                   # AdditionalHeader
    service_result
  end

  # The OPN response mirrors the request framing: a plaintext SecureChannelId,
  # the asymmetric security header, the sequence header, then the service body.
  def parse_open_response(body)
    cur = Cursor.new(body)
    cur.u32                # SecureChannelId
    cur.skip_string        # SecurityPolicyUri
    cur.skip_string        # SenderCertificate
    cur.skip_string        # ReceiverCertificateThumbprint
    cur.u32                # SequenceNumber
    cur.u32                # RequestId
    cur.skip_node_id       # TypeId
    service_result = parse_response_header(cur)
    cur.u32                # ServerProtocolVersion

    {
      service_result: service_result,
      channel_id: cur.u32,   # SecurityToken.ChannelId
      token_id: cur.u32      # SecurityToken.TokenId
    }
  end

  # GetEndpointsResponse: a ResponseHeader followed by EndpointDescription[].
  # The payload passed in already has the secure conversation prefix stripped.
  def parse_get_endpoints(payload)
    cur = Cursor.new(payload)
    cur.skip_node_id # TypeId
    service_result = parse_response_header(cur)
    return [nil, format('GetEndpoints ServiceResult=0x%08X', service_result)] unless service_result.zero?

    count = cur.array_length(MAX_ENDPOINTS)
    endpoints = Array.new(count) { parse_endpoint_description(cur) }
    [endpoints, nil]
  end

  # EndpointDescription (Part 4, section 7.10). Field order is fixed; every
  # variable length field must be consumed in sequence to keep the cursor
  # aligned for the next endpoint in the array.
  def parse_endpoint_description(cur)
    endpoint_url = cur.string

    # Server: ApplicationDescription (Part 4, section 7.2)
    application_uri = cur.string
    product_uri = cur.string
    application_name = cur.localized_text
    cur.u32                                       # ApplicationType
    cur.skip_string                               # GatewayServerUri
    cur.skip_string                               # DiscoveryProfileUri
    cur.array_length.times { cur.skip_string }    # DiscoveryUrls

    server_certificate = cur.bytestring
    security_mode = cur.u32
    security_policy_uri = cur.string

    # UserIdentityTokens: UserTokenPolicy[] (Part 4, section 7.37)
    token_count = cur.array_length
    tokens = Array.new(token_count) do
      policy_id = cur.string
      token_type = cur.u32
      cur.skip_string                             # IssuedTokenType
      cur.skip_string                             # IssuerEndpointUrl
      cur.skip_string                             # SecurityPolicyUri, per token
      {
        policy_id: policy_id,
        token_type: token_type,
        token_type_name: TOKEN_TYPES[token_type] || "Unknown(#{token_type})"
      }
    end

    cur.skip_string                               # TransportProfileUri
    security_level = cur.u8

    {
      endpoint_url: endpoint_url,
      application_uri: application_uri,
      product_uri: product_uri,
      application_name: application_name,
      server_certificate_len: server_certificate.nil? ? 0 : server_certificate.bytesize,
      security_mode: security_mode,
      security_mode_name: SECURITY_MODES[security_mode] || "Unknown(#{security_mode})",
      security_policy_uri: security_policy_uri,
      security_policy_name: short_policy(security_policy_uri),
      user_tokens: tokens,
      security_level: security_level
    }
  end

  def short_policy(uri)
    return 'Unknown' if uri.nil? || uri.empty?

    uri.include?('#') ? uri.rpartition('#').last : uri
  end

  # ---------------------------------------------------------------------------
  # Reporting
  # ---------------------------------------------------------------------------

  def unencrypted?(endpoint)
    endpoint[:security_mode_name] == 'None' || endpoint[:security_policy_name] == 'None'
  end

  def anonymous?(endpoint)
    endpoint[:user_tokens].any? { |t| t[:token_type].zero? }
  end

  def report_endpoints(ip, endpoints)
    weak = endpoints.count { |ep| unencrypted?(ep) && anonymous?(ep) }

    print_good("OPC-UA server enumerated - #{endpoints.length} endpoint(s), #{weak} unauthenticated and unencrypted")

    fingerprint = endpoints.map { |ep| ep[:application_uri] }.compact.first
    product = endpoints.map { |ep| ep[:product_uri] }.compact.first

    endpoints.each_with_index do |ep, idx|
      security = "#{ep[:security_policy_name]}/#{ep[:security_mode_name]}"
      identity = ep[:user_tokens].map { |t| t[:token_type_name] }.uniq.join(', ')
      identity = 'none advertised' if identity.empty?

      print_status("  [#{idx}] #{ep[:endpoint_url]}")
      print_status("      security: #{security}  identity: #{identity}")

      if unencrypted?(ep) && anonymous?(ep)
        print_warning('      endpoint accepts anonymous clients over an unencrypted channel')
      end
    end

    print_status("  ApplicationUri: #{fingerprint}") if fingerprint
    print_status("  ProductUri: #{product}") if product

    info = "OPC-UA server, #{endpoints.length} endpoint(s)"
    info << ", ApplicationUri #{fingerprint}" if fingerprint

    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'opc-ua',
      info: info
    )

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      type: 'opcua.endpoints',
      data: { endpoints: endpoints },
      update: :unique_data
    )

    return unless weak.positive?

    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'OPC-UA endpoint accepting anonymous identity without encryption',
      info: "#{weak} of #{endpoints.length} advertised endpoint(s) accept the Anonymous user identity token over a channel with MessageSecurityMode None",
      refs: references
    )
  end

  # ---------------------------------------------------------------------------
  # Scanner entry point
  # ---------------------------------------------------------------------------

  def run_host(ip)
    connect

    endpoint_url = "opc.tcp://#{Rex::Socket.to_authority(ip, rport)}"

    sock.put(build_hello(endpoint_url))
    msg = recv_message
    if msg.nil?
      vprint_status('No OPC-UA response to HEL')
      return
    end

    unless msg[0] == 'ACK'
      if msg[0] == 'ERR'
        status, reason = decode_error(msg[2])
        detail = reason.to_s.empty? ? status : "#{status} - #{reason}"
        print_status("OPC-UA server present but refused the Hello - #{detail}")
      else
        vprint_status("Non-OPC-UA response (type=#{msg[0].inspect})")
      end
      return
    end

    vprint_good('OPC-UA Hello acknowledged, opening secure channel')

    sock.put(build_open_secure_channel)
    msg = recv_message
    if msg.nil? || msg[0] != 'OPN'
      detail = msg.nil? ? 'no response' : "got #{msg[0].inspect}"
      print_status("OpenSecureChannel with SecurityPolicy=None failed (#{detail}); endpoints cannot be enumerated")
      return
    end

    channel = parse_open_response(msg[2])
    unless channel[:service_result].zero?
      print_status(format('OpenSecureChannel rejected, ServiceResult=0x%08X', channel[:service_result]))
      return
    end

    sock.put(build_get_endpoints(channel[:channel_id], channel[:token_id], endpoint_url))
    payload, error = recv_service_response
    if payload.nil?
      print_error("GetEndpoints failed: #{error}")
      return
    end

    endpoints, error = parse_get_endpoints(payload)
    if endpoints.nil?
      print_error(error)
      return
    end

    if endpoints.empty?
      print_status('OPC-UA server returned no endpoints')
      return
    end

    report_endpoints(ip, endpoints)

    # Release the channel rather than leaving it open until its lifetime expires.
    begin
      sock.put(build_close_secure_channel(channel[:channel_id], channel[:token_id]))
    rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET, ::Errno::EPIPE
      nil
    end
  rescue UaParseError => e
    print_error("Malformed OPC-UA response: #{e.message}")
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET => e
    vprint_error("#{e.class}: #{e.message}")
  ensure
    disconnect
  end
end
