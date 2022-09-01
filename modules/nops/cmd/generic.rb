##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Nop
  def initialize
    super(
      'Name' => 'Generic Command Nop Generator',
      'Alias' => 'cmd_generic',
      'Description' => 'Generates harmless padding for command payloads.',
      'Author' => ['hdm', 'bcoles'],
      'License' => MSF_LICENSE,
      'Arch' => ARCH_CMD)
  end

  # Generate valid commands up to the requested length
  def generate_sled(length, _opts = {})
    # Default to just spaces for now
    ' ' * length
  end
end
