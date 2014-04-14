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
          This module attempts to identify F5 SLB and decode sticky cookies wich leak
        backend IP and port.
      },
      'Author'         => [ 'Thanat0s' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to test', '/']),
        OptInt.new('RETRY', [true, 'Number of requests to find backends', 10])
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

  def get_cook
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri
    })

    #puts res.get_cookies
    begin
      # Get the SLB session ID, like "TestCookie=2263487148.3013.0000"
      m = res.headers['Set-Cookie'].match(/([\-\w\d]+)=((?:\d+\.){2}\d+)(?:$|,|;|\s)/)
      # m = res.get_cookies.match(/([\-\w\d]+)=((?:\d+\.){2}\d+)(?:$|,|;|\s)/)
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
    id, value = get_cook()
    if id
      print_status "F5 cookie \"#{id}\" found"
      host, port = cookie_decode(value)
      host_port[host+":"+port] = true
      print_status "Backend #{host}:#{port}"
      i=1 # We already have done one request
      until i == datastore['RETRY']
        id, value = get_cook()
        host, port = cookie_decode(value)
        unless ! host_port[host+":"+port].nil?
          host_port[host+":"+port] = true
          print_status "Backend #{host}:#{port}"
        end
        i += 1
      end
    else
      print_error "F5 SLB cookie not found"
    end
  end
end
