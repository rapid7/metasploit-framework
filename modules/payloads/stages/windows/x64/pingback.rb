##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows'
require 'msf/base/sessions/pingback'

module MetasploitModule

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows x64 Pingback',
      'Description'   => 'Just enough payload to verify RCE',
      'Author'        => 'Brent Cook',
      'Platform'      => 'windows',
      'Arch'          => ARCH_X64,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Pingback
    ))
  end

  def generate_stage(opts={})
    return nil
  end
end
