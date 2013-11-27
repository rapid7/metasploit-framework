##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HttpClient Cookie Tester',
      'Description'    => %q{C is for cookie},
      'References'     =>
        [
          [ 'URL', 'http://metasploit.com' ],
        ],
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Nov 26 2013"
    ))
  end

  #
  # This tests against a single host
  #
  def test1
    # This request doesn't have a cookie sent, so the server will set one for us
    print_status("Sending a normal request")
    res = send_request_cgi({'uri'=>'/'})

    # This time will send a cookie from what the server gave us.
    res = send_request_cgi({'uri'=>'/'})

    # This time we've decided to be naughty. We modify the cookie and send it to the server
    cookie = res.headers['cookie']
    print_status("Original cookie: #{cookie.inspect}")
    cookie = "JSESSIONID=MSFTEST; Path=/; HttpOnly"
    print_status("Sending this cookie: #{cookie}")
    send_request_cgi({
      'uri'    => '/',
      'cookie' => cookie
    })
  end

  #
  # This tests against multiple hosts
  # We don't really recommend people to do something like this, but HttpClient is capable.
  # Host A's cookie shouldn't be sent to Host B by the mixin.
  #
  def test2
    print_status("Getting a cookie from host A")
    res = send_request_cgi({'uri'=>'/'})

    print_status("Getting a cookie from google.com")
    datastore['RHOST'] = "74.125.30.101"
    res = send_request_cgi({'uri'=>'/'})

    print_status("Sending another HTTP request")
    res = send_request_cgi({'uri'=>'/'})
  end

  def run
    print_status("You'll need to run a traffic sniffer to verify this")

    print_status("Testing against a single host")
    test1

    print_line
    print_line
    print_line

    print_status("Testing against multiple hosts")
    test2
  end

end