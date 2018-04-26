##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This class implements a "nop" generator for PHP payloads
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'PHP Nop Generator',
      'Alias'       => 'php_generic',
      'Description' => 'Generates harmless padding for PHP scripts',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_PHP)
  end

  # Generate valid PHP code up to the requested length
  def generate_sled(length, opts = {})
    # Default to just spaces for now
    " " * length
  end
end
