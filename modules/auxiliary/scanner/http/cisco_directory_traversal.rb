##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco ASA Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in Cisco's Adaptive Security Appliance (ASA) software and Firepower Threat Defense (FTD) software.
      },
      'Author'         => [ 'Michał Bentkowski',  # Discovery
                            'Yassine Aboukir',    # PoC
                            'Shelby Pace'         # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                           [ 'CVE', '2018-0296' ],
                           [ 'EDB', '44956' ]
                          ],
      'DisclosureDate' => 'Jun 6 2018'
    ))
  end

  def run
  end

end

