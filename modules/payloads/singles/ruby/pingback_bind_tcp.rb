require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/ruby'

require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = 147

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Sessions::PingbackOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Ruby Pingback, Bind TCP',
      'Description' => 'Listens for a connection from the attacker, sends a UUID, then terminates',
      'Author' => 'asoto-r7',
      'License' => MSF_LICENSE,
      'Platform' => 'ruby',
      'Arch' => ARCH_RUBY,
      'Handler' => Msf::Handler::BindTcp,
      'Session' => Msf::Sessions::Pingback,
      'PayloadType' => 'ruby',
      'Payload' =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  def generate
    #return prepends(ruby_string)
    return ruby_string
  end

  def ruby_string
    pingback_uuid ||= generate_pingback_uuid
    pingback_uuid.gsub!('-','')

    return "require 'socket';"+
      "s=TCPServer.new(#{datastore['LPORT'].to_i});"+
      "c=s.accept;"+
      "s.close;"+
      "c.puts(\'#{pingback_uuid}\'.scan(/../).map { |x| x.hex.chr }.join);"+
      "c.close"
 end

  def include_send_pingback
    true
  end
end


