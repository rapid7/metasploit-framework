##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/directadmin'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'DirectAdmin Web Control Panel Login Utility',
      'Description' => %q{
        This module will attempt to authenticate to a DirectAdmin Web Control Panel.
      },
      'Author'      => [ 'Nick Marcoccio "1oopho1e" <iremembermodems[at]gmail.com>' ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'RPORT'      => 2222,
          'SSL'        => true,
        }
    ))

    register_options(
      [
        OptString.new('USERNAME', [false, 'The username to specify for authentication', '']),
        OptString.new('PASSWORD', [false, 'The password to specify for authentication', '']),
      ])
  end


  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file:       datastore['PASS_FILE'],
        password:        datastore['PASSWORD'],
        user_file:       datastore['USER_FILE'],
        userpass_file:   datastore['USERPASS_FILE'],
        username:        datastore['USERNAME'],
        user_as_pass:    datastore['USER_AS_PASS']
      )

      return Metasploit::Framework::LoginScanner::DirectAdmin.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          cred_details:       cred_collection,
          stop_on_success:    datastore['STOP_ON_SUCCESS'],
          bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 5,
          http_username:      datastore['HttpUsername'],
          http_password:      datastore['HttpPassword']
        ))
    }.call
  end

  # Attempts to login
  def bruteforce(ip)
    scanner(ip).scan! do |result|
      credential_data = result.to_h.merge({
        workspace_id: myworkspace_id,
        module_fullname: self.fullname,
      })
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
        create_credential_and_login(credential_data)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
        invalidate_login(credential_data)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
        invalidate_login(credential_data)
      end
    end
  end


  # Start here
  def run_host(ip)
    unless scanner(ip).check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Target is not DirectAdmin Web Control Panel')
      return
    end

    bruteforce(ip)
  end
end
