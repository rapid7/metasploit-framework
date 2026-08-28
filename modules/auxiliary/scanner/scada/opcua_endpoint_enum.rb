# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # The OPC-UA transport, its records, its enumerations and its errors. Every
  # byte level concern lives there: framing, chunk reassembly, the built-in type
  # encodings and the service structures, all of them checked against
  # reference/opcua and the captures under spec/file_fixtures/opc_ua. What is
  # left here is the scan itself.
  #
  # The ceilings that bound a hostile response live there too, and are the only
  # thing standing between this module and unbounded allocation:
  #
  #   Rex::Proto::OpcUa::Tcp::MAX_MESSAGE_SIZE    one message, 4 MiB
  #   Rex::Proto::OpcUa::Tcp::MAX_CHUNKS          chunks per response, 64
  #   Rex::Proto::OpcUa::Services::MAX_ENDPOINTS  endpoints per response, 64
  #   Rex::Proto::OpcUa::Types::OpcUaArray::DEFAULT_MAX_LENGTH   any other
  #                                               array, 512
  OpcUa = Rex::Proto::OpcUa

  # ProtocolVersion 0 is the only version this standard defines. The buffer
  # sizes are what this client is willing to receive; zero for MaxMessageSize
  # and MaxChunkCount says the client imposes no limit of its own, which is not
  # the same as accepting anything, since the ceilings above apply regardless.
  # See OPC-UA Specification Part 6, section 7.1.2.3.
  HELLO_BUFFER_SIZE = 65_535

  # TimeoutHint on every request, in milliseconds.
  REQUEST_TIMEOUT_MS = 10_000

  # RequestedLifetime for the secure channel, in milliseconds. The server
  # answers with a revised lifetime it is prepared to honour.
  CHANNEL_LIFETIME_MS = 3_600_000

  # MessageSecurityMode None (Part 4, section 7.20, Table 139). The channel is
  # opened unprotected because GetEndpoints is reachable that way by
  # specification and the module reads nothing else.
  SECURITY_MODE_NONE = 1

  # UserTokenType Anonymous (Part 4, section 7.42, Table 193).
  TOKEN_TYPE_ANONYMOUS = 0

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
  # Requests
  # ---------------------------------------------------------------------------

  # Fields common to every request header. The AuthenticationToken and
  # AuditEntryId are left to their defaults, which are the null NodeId of a
  # sessionless request and a null String.
  #
  # @param handle [Integer] the RequestHandle, which pairs a response with the
  #   request that asked for it.
  # @return [Hash] fields for a Rex::Proto::OpcUa::Services::RequestHeader.
  def request_header_fields(handle)
    {
      timestamp: OpcUa::Types::OpcUaDateTime.now,
      request_handle: handle,
      return_diagnostics: 0,
      timeout_hint: REQUEST_TIMEOUT_MS
    }
  end

  # The TypeId that names the service a message body carries. Every service
  # identifier this module uses is a FourByte NodeId in namespace 0.
  #
  # @param identifier [Integer] a Rex::Proto::OpcUa::Enums::NodeIds value.
  # @return [String] the encoded NodeId.
  def type_id(identifier)
    OpcUa::Types::OpcUaNodeId.four_byte(identifier).to_binary_s
  end

  # @param stream [Rex::Proto::OpcUa::Tcp::MessageStream]
  # @param endpoint_url [String] the URL this client believes it dialled.
  # @return [Integer] bytes written.
  def send_hello(stream, endpoint_url)
    hello = OpcUa::Tcp::HelloMessage.new(
      protocol_version: 0,
      receive_buffer_size: HELLO_BUFFER_SIZE,
      send_buffer_size: HELLO_BUFFER_SIZE,
      max_message_size: 0,
      max_chunk_count: 0,
      endpoint_url: endpoint_url
    )

    stream.send_message(OpcUa::Tcp::MessageType::HELLO, hello.to_binary_s)
  end

  # An OPN message body: a plaintext SecureChannelId, the asymmetric security
  # header, the sequence header, then the TypeId and the service request. Under
  # SecurityPolicy None the certificate fields of the security header are null
  # and no cryptography is applied to this or any later message on the channel.
  #
  # @param stream [Rex::Proto::OpcUa::Tcp::MessageStream]
  # @return [Integer] bytes written.
  def send_open_secure_channel(stream)
    # SecureChannelId, zero because the channel does not exist yet.
    body = [0].pack('V')
    body << OpcUa::SecureChannel::AsymmetricSecurityHeader.new(
      security_policy_uri: OpcUa::Enums::NONE_POLICY_URI
    ).to_binary_s
    body << OpcUa::SecureChannel::SequenceHeader.new(sequence_number: 1, request_id: 1).to_binary_s
    body << type_id(OpcUa::Enums::NodeIds::OPEN_SECURE_CHANNEL_REQUEST)
    body << OpcUa::SecureChannel::OpenSecureChannelRequest.new(
      request_header: request_header_fields(1),
      client_protocol_version: 0,
      request_type: OpcUa::SecureChannel::OpenSecureChannelRequest::ISSUE,
      security_mode: SECURITY_MODE_NONE,
      requested_lifetime: CHANNEL_LIFETIME_MS
    ).to_binary_s

    stream.send_message(OpcUa::Tcp::MessageType::OPEN_SECURE_CHANNEL, body)
  end

  # A MSG or CLO body on an open channel: the SecureChannelId and TokenId the
  # server issued, the sequence header, then the TypeId and the service request.
  #
  # @param token [Rex::Proto::OpcUa::SecureChannel::ChannelSecurityToken]
  # @param sequence [Integer] SequenceNumber and RequestId for this message.
  # @param request [String] the TypeId and encoded service request.
  # @return [String] the message body.
  def channel_body(token, sequence, request)
    body = [token.channel_id.snapshot].pack('V')
    body << OpcUa::SecureChannel::SymmetricSecurityHeader.new(token_id: token.token_id.snapshot).to_binary_s
    body << OpcUa::SecureChannel::SequenceHeader.new(sequence_number: sequence, request_id: sequence).to_binary_s
    body << request
    body
  end

  # @param stream [Rex::Proto::OpcUa::Tcp::MessageStream]
  # @param token [Rex::Proto::OpcUa::SecureChannel::ChannelSecurityToken]
  # @param endpoint_url [String] the URL this client believes it dialled.
  # @return [Integer] bytes written.
  def send_get_endpoints(stream, token, endpoint_url)
    # LocaleIds and ProfileUris are filters and default to null, which asks for
    # every endpoint the server has.
    request = type_id(OpcUa::Enums::NodeIds::GET_ENDPOINTS_REQUEST)
    request << OpcUa::Services::GetEndpointsRequest.new(
      request_header: request_header_fields(2),
      endpoint_url: endpoint_url
    ).to_binary_s

    stream.send_message(OpcUa::Tcp::MessageType::MESSAGE, channel_body(token, 2, request))
  end

  # @param stream [Rex::Proto::OpcUa::Tcp::MessageStream]
  # @param token [Rex::Proto::OpcUa::SecureChannel::ChannelSecurityToken]
  # @return [Integer] bytes written.
  def send_close_secure_channel(stream, token)
    request = type_id(OpcUa::Enums::NodeIds::CLOSE_SECURE_CHANNEL_REQUEST)
    request << OpcUa::SecureChannel::CloseSecureChannelRequest.new(
      request_header: request_header_fields(3)
    ).to_binary_s

    stream.send_message(OpcUa::Tcp::MessageType::CLOSE_SECURE_CHANNEL, channel_body(token, 3, request))
  end

  # ---------------------------------------------------------------------------
  # Responses
  # ---------------------------------------------------------------------------

  # The StatusCode of an ERR message, by name, with the Reason appended when the
  # server supplied one.
  #
  # @param body [String] the ERR message body.
  # @return [String] the detail to show the user.
  def error_detail(body)
    status_code, reason = OpcUa::Tcp::ErrorMessage.decode(body)
    return 'unknown' if status_code.nil?

    name = OpcUa::Enums.status_code_name(status_code)
    reason.to_s.empty? ? name : "#{name} - #{reason}"
  end

  # The payload handed back by the transport begins at the response TypeId,
  # which says which service answered.
  #
  # @param payload [String] the reassembled service payload.
  # @return [Rex::Proto::OpcUa::Services::GetEndpointsResponse]
  def parse_get_endpoints(payload)
    type_id = OpcUa::Types::OpcUaNodeId.read(payload)

    OpcUa::Services::GetEndpointsResponse.read(payload.byteslice(type_id.num_bytes..-1).to_s)
  end

  # Flatten an EndpointDescription into the shape this module reports and files
  # in the database. The keys and their order are what report_note serialises
  # and what the module documentation describes, so they are part of the
  # module's interface rather than an implementation detail.
  #
  # @param endpoint [Rex::Proto::OpcUa::Services::EndpointDescription]
  # @return [Hash]
  def present(endpoint)
    server = endpoint.server
    name = server.application_name
    certificate = endpoint.server_certificate.snapshot
    mode = endpoint.security_mode.snapshot
    policy_uri = endpoint.security_policy_uri.snapshot

    {
      endpoint_url: endpoint.endpoint_url.snapshot,
      application_uri: server.application_uri.snapshot,
      product_uri: server.product_uri.snapshot,
      application_name: name.text? ? name.text.snapshot : nil,
      # The length rather than the certificate: the note goes to the database
      # and there is nothing to be learned from storing the whole blob.
      server_certificate_len: certificate.nil? ? 0 : certificate.bytesize,
      security_mode: mode,
      security_mode_name: OpcUa::Enums.security_mode_name(mode),
      security_policy_uri: policy_uri,
      security_policy_name: OpcUa::Enums.security_policy_name(policy_uri),
      user_tokens: endpoint.user_identity_tokens.map { |token| present_token(token) },
      security_level: endpoint.security_level.snapshot
    }
  end

  # @param token [Rex::Proto::OpcUa::Services::UserTokenPolicy]
  # @return [Hash]
  def present_token(token)
    token_type = token.token_type.snapshot

    {
      policy_id: token.policy_id.snapshot,
      token_type: token_type,
      token_type_name: OpcUa::Enums.user_token_type_name(token_type)
    }
  end

  # ---------------------------------------------------------------------------
  # Reporting
  # ---------------------------------------------------------------------------

  def unencrypted?(endpoint)
    endpoint[:security_mode_name] == 'None' || endpoint[:security_policy_name] == 'None'
  end

  def anonymous?(endpoint)
    endpoint[:user_tokens].any? { |t| t[:token_type] == TOKEN_TYPE_ANONYMOUS }
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

  # Say hello and read the acknowledgement.
  #
  # A framing error is reported the same way as silence, because from the far
  # side of a scan they are the same thing: whatever answered is not speaking
  # this protocol, and there is nothing further to try.
  #
  # @return [Boolean] whether the server acknowledged.
  def hello_acknowledged?(stream, endpoint_url)
    send_hello(stream, endpoint_url)

    begin
      msg = stream.recv_message
    rescue OpcUa::Error::OpcUaError
      vprint_status('No OPC-UA response to HEL')
      return false
    end

    return true if msg.message_type == OpcUa::Tcp::MessageType::ACKNOWLEDGE

    if msg.error?
      print_status("OPC-UA server present but refused the Hello - #{error_detail(msg.body)}")
    else
      vprint_status("Non-OPC-UA response (type=#{msg.message_type.inspect})")
    end
    false
  end

  # @return [Rex::Proto::OpcUa::SecureChannel::ChannelSecurityToken, nil] the
  #   token to quote on later messages, or nil if the channel did not open.
  def open_secure_channel(stream)
    send_open_secure_channel(stream)

    msg = begin
      stream.recv_message
    rescue OpcUa::Error::OpcUaError
      nil
    end

    if msg.nil? || msg.message_type != OpcUa::Tcp::MessageType::OPEN_SECURE_CHANNEL
      detail = msg.nil? ? 'no response' : "got #{msg.message_type.inspect}"
      print_status("OpenSecureChannel with SecurityPolicy=None failed (#{detail}); endpoints cannot be enumerated")
      return nil
    end

    response = OpcUa::SecureChannel.parse_open_response(msg.body)
    service_result = response.response_header.service_result.snapshot
    unless service_result.zero?
      print_status(format('OpenSecureChannel rejected, ServiceResult=0x%08X', service_result))
      return nil
    end

    response.security_token
  end

  # Read the GetEndpoints response, reporting why it did not arrive.
  #
  # 'no response' is the detail for silence specifically; every other failure
  # carries the account the error itself gives, which for an ERR or an abort is
  # the StatusCode the server sent.
  #
  # @param stream [Rex::Proto::OpcUa::Tcp::MessageStream]
  # @return [String, nil] the reassembled service payload, or nil on failure.
  def read_service_response(stream)
    stream.recv_service_response
  rescue OpcUa::Error::TimeoutError
    print_error('GetEndpoints failed: no response')
    nil
  rescue OpcUa::Error::OpcUaError => e
    print_error("GetEndpoints failed: #{e.message}")
    nil
  end

  # @return [Array<Hash>, nil] the endpoints in report shape, or nil on failure.
  def enumerate_endpoints(stream, token, endpoint_url)
    send_get_endpoints(stream, token, endpoint_url)

    payload = read_service_response(stream)
    return nil if payload.nil?

    response = parse_get_endpoints(payload)
    service_result = response.response_header.service_result.snapshot
    unless service_result.zero?
      print_error(format('GetEndpoints ServiceResult=0x%08X', service_result))
      return nil
    end

    response.endpoints.map { |endpoint| present(endpoint) }
  end

  def run_host(ip)
    connect

    stream = OpcUa::Tcp::MessageStream.new(sock, timeout: read_timeout)
    endpoint_url = "opc.tcp://#{Rex::Socket.to_authority(ip, rport)}"

    return unless hello_acknowledged?(stream, endpoint_url)

    vprint_good('OPC-UA Hello acknowledged, opening secure channel')

    token = open_secure_channel(stream)
    return if token.nil?

    endpoints = enumerate_endpoints(stream, token, endpoint_url)
    return if endpoints.nil?

    if endpoints.empty?
      print_status('OPC-UA server returned no endpoints')
      return
    end

    report_endpoints(ip, endpoints)

    # Release the channel rather than leaving it open until its lifetime
    # expires. Nothing is read back; the scan is finished either way.
    begin
      send_close_secure_channel(stream, token)
    rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET, ::Errno::EPIPE
      nil
    end
  # Every error the library raises descends from Rex::RuntimeError, and
  # Msf::Auxiliary::Scanner re-raises a bare ::RuntimeError out of its per host
  # loop rather than moving to the next host. One malformed server would
  # otherwise end a whole sweep, so the family is caught here as well as at each
  # step that expects it.
  rescue OpcUa::Error::OpcUaError => e
    vprint_error("OPC-UA transport error: #{e.message}")
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET => e
    vprint_error("#{e.class}: #{e.message}")
  # A record that will not decode raises from BinData rather than from the
  # library. EOFError is an IOError, so it has to be caught above this.
  rescue ::BinData::ValidityError, ::IOError => e
    print_error("Malformed OPC-UA response: #{e.message}")
  ensure
    disconnect
  end
end
