##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module Metasploit
  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name'          => 'Tidy Payload for RSpec',
        'Description'   => 'Test!'
      )
    )
  end
end
