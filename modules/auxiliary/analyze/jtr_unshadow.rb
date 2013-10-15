##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

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

    unshadow = john_unshadow(datastore['PASSWD_PATH'],datastore['SHADOW_PATH'])
    if unshadow
      print_good(unshadow)
      filename= "#{datastore['IP']}_Linux_Hashes.txt"
      lootfile = store_loot("linux.hashes", "text/plain", datastore['IP'], unshadow, filename, "Linux Hashes")
      print_status("Saved unshadowed file: #{lootfile}")
    end
  end

end
