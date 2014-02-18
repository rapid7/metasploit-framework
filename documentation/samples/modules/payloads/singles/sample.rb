##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#
# This sample payload is designed to trigger a debugger exception via int3.
#
###
module Metasploit4

  include Msf::Payload::Single

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Debugger Trap',
      'Description'   => 'Causes a debugger trap exception through int3',
      'License'       => MSF_LICENSE,
      'Author'        => 'skape',
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Payload'       =>
        {
          'Payload' => "\xcc"
        }
      ))
  end

end
