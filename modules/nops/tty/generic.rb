##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This class implements a "nop" generator for TTY payloads
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'TTY Nop Generator',
      'Alias'       => 'tty_generic',
      'Description' => 'Generates harmless padding for TTY input',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_TTY)
  end

  # Generate valid PHP code up to the requested length
  def generate_sled(length, opts = {})
    # Default to just spaces for now
    " " * length
  end
end
