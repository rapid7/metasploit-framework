##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#
# This class implements a very basic NOP sled generator that just returns a
# string of 0x90's.
#
###
class Metasploit4 < Msf::Nop

  def initialize
    super(
      'Name'        => 'Sample NOP Generator',
      'Description' => 'Sample single-byte NOP generator',
      'License'     => MSF_LICENSE,
      'Author'      => 'skape',
      'Arch'        => ARCH_X86)
  end

  #
  # Returns a string of 0x90's for the supplied length.
  #
  def generate_sled(length, opts)
    "\x90" * length
  end

end
