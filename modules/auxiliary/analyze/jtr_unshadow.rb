##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  def initialize
    super(
      'Name'              => 'Unix Unshadow Utility',
      'Description'       => %Q{
          This module takes a passwd and shadow file and 'unshadows'
          them and saves them as linux.hashes loot.
      },
      'Author'            => ['theLightCosine'],
      'License'           => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('PASSWD_PATH', [true, 'The path to the passwd file']),
        OptPath.new('SHADOW_PATH', [true, 'The path to the shadow file']),
        OptAddress.new('IP', [true, 'The IP address if the host the shadow file came from']),
      ], self.class)
  end

  def run
    print_error "This module is deprecated and does nothing. It will be removed in the next release!"
  end

end
