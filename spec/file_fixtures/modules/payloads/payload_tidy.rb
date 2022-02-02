##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule
  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Tidy Payload for RSpec',
      'Description' => 'Test!',
      'Author'      => 'Unknown',
      'License'     => MSF_LICENSE
    ))
  end
end
