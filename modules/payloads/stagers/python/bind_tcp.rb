##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/python'
require 'msf/core/payload/python/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 386

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Bind TCP Stager',
      'Description' => 'Listen for a connection',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::BindTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end
end
