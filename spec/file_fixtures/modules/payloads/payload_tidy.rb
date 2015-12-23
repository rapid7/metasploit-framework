##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module Metasploit4
  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name'          => 'Unix Command Shell, Bind TCP (via AWK)',
        'Description'   => 'Listen for a connection and spawn a command shell via GNU AWK',
      )
    )
  end
end
