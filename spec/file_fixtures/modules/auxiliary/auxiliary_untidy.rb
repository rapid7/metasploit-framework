##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

# XXX: invalid super class for an auxiliary module
class MetasploitModule < Msf::Exploit
  # XXX: auxiliary modules don't use Rank
  Rank = LowRanking
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'            => 'Untidy Auxiliary Module for RSpec'
        'Description'     => 'Test!'
        },
        'Author'         => %w(Unknown),
        'License'        => MSF_LICENSE,
      )
    )
  end
end
