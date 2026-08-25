# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # OPC-UA Connection Protocol message header is 8 bytes:
  #   MessageType (3 bytes ASCII) + ChunkType (1 byte ASCII) + MessageSize (UInt32 LE)
  HEADER_LEN = 8

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

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OPC-UA Server Detection',
        'Description' => %q{
          This module detects OPC-UA servers speaking the OPC-UA TCP binary
          transport (opc.tcp://) by sending a Hello (HEL) message and inspecting
          the response. A server that replies with an Acknowledge (ACK) message
          accepted the connection. A server that replies with an Error (ERR)
          message is still a confirmed OPC-UA server; the returned StatusCode and
          reason are reported. OPC-UA is widely deployed in industrial control
          systems, including as the standard server interface on Inductive
          Automation Ignition gateways.
        },
        'Author' => [
          'Ethan Thomason <ethan@ethomason.com>'
        ],
        'References' => [
          ['URL', 'https://reference.opcfoundation.org/Core/Part6/'],
          ['URL', 'https://opcfoundation.org/about/opc-technologies/opc-ua/']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(4840)
      ]
    )
  end

  # Build an OPC-UA Hello (HEL) message for the given endpoint URL.
  # Body layout (all UInt32 little-endian, then a UA String for the URL):
  #   ProtocolVersion + ReceiveBufferSize + SendBufferSize +
  #   MaxMessageSize + MaxChunkCount + EndpointUrlLength + EndpointUrl
  def build_hello(endpoint_url)
    body = [
      0,      # ProtocolVersion
      65535,  # ReceiveBufferSize
      65535,  # SendBufferSize
      0,      # MaxMessageSize (0 = no limit)
      0       # MaxChunkCount  (0 = no limit)
    ].pack('V*')
    body << [endpoint_url.length].pack('V') << endpoint_url

    msg_size = HEADER_LEN + body.length
    'HELF' + [msg_size].pack('V') + body
  end

  # Decode an ERR message body: UInt32 StatusCode + UA String reason.
  # Returns [status_string, reason_string].
  def decode_error(body)
    return ['unknown', ''] if body.length < 4

    code = body[0, 4].unpack1('V')
    status = STATUS_CODES[code] || format('0x%08X', code)

    reason = ''
    if body.length >= 8
      reason_len = body[4, 4].unpack1('V')
      # UA String length 0xFFFFFFFF denotes null; otherwise read the bytes.
      if reason_len != 0xFFFFFFFF && reason_len.positive? && body.length >= 8 + reason_len
        reason = body[8, reason_len]
      end
    end

    [status, reason]
  end

  def run_host(ip)
    connect

    endpoint_url = "opc.tcp://#{Rex::Socket.to_authority(ip, rport)}"
    sock.put(build_hello(endpoint_url))

    data = sock.get_once(-1, 5)

    if data.nil? || data.length < 4
      vprint_status('No OPC-UA response to HEL')
      return
    end

    msg_type = data[0, 3]
    chunk_type = data[3, 1]
    body = data.length > HEADER_LEN ? data[HEADER_LEN..] : ''

    case msg_type
    when 'ACK'
      info = 'accepted connection'
      if body.length >= 12
        proto_ver, rcv_buf, snd_buf = body.unpack('VVV')
        info = "ProtocolVersion=#{proto_ver} RecvBuf=#{rcv_buf} SendBuf=#{snd_buf}"
      end
      print_good("OPC-UA server detected (ACK) - #{info}")
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'opc-ua',
        info: "OPC-UA server (ACK): #{info}"
      )
    when 'ERR'
      status, reason = decode_error(body)
      detail = reason.empty? ? status : "#{status} - #{reason}"
      print_good("OPC-UA server detected (ERR) - #{detail}")
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'opc-ua',
        info: "OPC-UA server (ERR): #{detail}"
      )
    else
      vprint_status("Non-OPC-UA response (type=#{msg_type.inspect} chunk=#{chunk_type.inspect})")
    end
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET => e
    vprint_error("#{e.class}: #{e.message}")
  ensure
    disconnect
  end
end
