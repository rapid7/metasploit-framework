##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Module name',
      'Description'    => %q{
        Say something that the user might want to know.
      },
      'Author'         => [ 'Thongchai Silpavarangkura', # PoC
                            'N. Rai-Ngoen',              # PoC
                            'Shelby Pace'                # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-14058' ],
                            [ 'EDB', '45208']
                          ],
      'DisclosureDate' => 'Aug 13, 2018'
    ))

    register_options(
      [
      ]
    )
  end

  def run
  end

end
