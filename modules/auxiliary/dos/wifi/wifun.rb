##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wireless Test Module',
      'Description'    => %q{
        This module is a test of the wireless packet injection system.
      Please see external/ruby-lorcon/README for more information.
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
  end

  def run
    open_wifi
    wifi.write("X" * 1000)
  end

end
