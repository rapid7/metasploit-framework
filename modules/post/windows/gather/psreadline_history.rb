##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/user_profiles'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
        'Name' => 'Windows Gather PSReadline history',
        'Description' => %q{
          Gathers Power Shell history data from the target machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Garvit Dewan <d.garvit[at]gmail.com>' # @dgarvit
        ],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  def run

  end
