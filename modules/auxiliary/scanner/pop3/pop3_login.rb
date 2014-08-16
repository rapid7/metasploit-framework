##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/login_scanner/pop3'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
  super(
    'Name'        => 'POP3 Login Utility',
    'Description' => 'This module attempts to authenticate to an POP3 service.',
    'Author'      =>
    [
      '==[ Alligator Security Team ]==',
      'Heyder Andrade <heyder[at]alligatorteam.org>'
    ],
      'References'     =>
    [
      ['URL', 'http://www.ietf.org/rfc/rfc1734.txt'],
      ['URL', 'http://www.ietf.org/rfc/rfc1939.txt'],
    ],
      'License'     => MSF_LICENSE
  )
  register_options(
    [
      Opt::RPORT(110),
      OptPath.new('USER_FILE',
        [
          false,
          'The file that contains a list of probable users accounts.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
        ]),
      OptPath.new('PASS_FILE',
        [
          false,
          'The file that contains a list of probable passwords.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
        ])
    ], self.class)
  end

  def target
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS'],
    )

    scanner = Metasploit::Framework::LoginScanner::POP3.new(
      host: ip,
      port: rport,
      ssl: datastore['SSL'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
    )

    scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        do_report(result)
        next
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
      when Metasploit::Model::Login::Status::INCORRECT
        print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}', '#{result.proof.to_s.chomp}'"
      end

      # If we got here, it didn't work
      invalidate_login(
        address: ip,
        port: rport,
        protocol: 'tcp',
        public: result.credential.public,
        private: result.credential.private,
        realm_key: result.credential.realm_key,
        realm_value: result.credential.realm,
        status: result.status
      )
    end
  end

  def service_name
    datastore['SSL'] ? 'pop3s' : 'pop3'
  end

  def do_report(result)
    service_data = {
      address: rhost,
      port: rport,
      service_name: service_name,
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

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: result.status
    }.merge(service_data)

    create_credential_login(login_data)
  end

end
