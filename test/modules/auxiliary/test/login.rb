##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'Test Login Scanner',
      'Description' => %q{
        Use this module to test how credentials are generated for login scanners.
      },
      'Author' => [
        'Spencer McIntyre'
      ],
      'References' => [
        [ 'CVE', '1999-0506'], # Weak password
      ],
      'DefaultOptions' => { 'RHOSTS' => '192.0.2.1' },
      'License' => MSF_LICENSE
    )
  end

  def run_host(ip)
    print_brute(level: :vstatus, ip: ip, msg: 'Starting login bruteforce')

    @scanner = TestLoginScanner.new(
      host: ip,
      port: 80,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      proxies: datastore['Proxies'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      framework: framework,
      framework_module: self
    )

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )
    cred_collection = prepend_db_hashes(cred_collection)

    @scanner.cred_details = cred_collection

    @scanner.each_credential do |credential|
      print_status("username: #{credential.public.inspect}, password: #{credential.private.inspect}")
    end
  end

  class TestLoginScanner
    include Metasploit::Framework::LoginScanner::Base

    REALM_KEY = nil

    def attempt_login(credential)
     ::Metasploit::Framework::LoginScanner::Result.new(
        host: host,
        port: port,
        protocol: 'tcp',
        credential: credential,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      )
    end
  end
end
