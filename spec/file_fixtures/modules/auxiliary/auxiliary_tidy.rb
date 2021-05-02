##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Tidy Auxiliary Module for RSpec'
      'Description' => 'Test!'
      'Author'      => 'Unknown',
      'License'     => MSF_LICENSE
    ))
  end
end
