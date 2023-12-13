##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mssql'
require 'metasploit/framework/mssql/client' 

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::MSSQL::Client
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MSSQL Login Utility',
      'Description'    => 'This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).',
      'Author'         => 'MC',
      'References'     =>
        [
          [ 'CVE', '1999-0506'] # Weak password
        ],
      'License'        => MSF_LICENSE,
      # some overrides from authbrute since there is a default username and a blank password
      'DefaultOptions' =>
        {
          'USERNAME' => 'sa',
          'BLANK_PASSWORDS' => true
        }
    )
    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(1433),
        OptString.new('USERNAME', [ false, 'The username to authenticate as', 'sa']),
        OptString.new('PASSWORD', [ false, 'The password for the specified username', '']),
        OptBool.new('TDSENCRYPTION', [ true, 'Use TLS/SSL for TDS data "Force Encryption"', false]),
        OptBool.new('USE_WINDOWS_AUTHENT', [ true, 'Use windows authentication (requires DOMAIN option set)', false]),
      ])

    set_sane_defaults

    deregister_options('PASSWORD_SPRAY')
  end

  def run_host(ip)
    print_status("#{rhost}:#{rport} - MSSQL - Starting authentication scanner.")

    if datastore['TDSENCRYPTION']
      print_status("Manually enabled TLS/SSL to encrypt TDS payloads.")
    end

    cred_collection = build_credential_collection(
        realm: datastore['DOMAIN'],
        username: datastore['USERNAME'],
        password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::MSSQL.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 30,
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        auth: datastore['Mssql::Auth'],
        domain_controller_rhost: datastore['DomainControllerRhost'],
        hostname: datastore['Mssql::Rhostname'],
        windows_authentication: datastore['USE_WINDOWS_AUTHENT'],
        tdsencryption: datastore['TDSENCRYPTION'],
        framework: framework,
        framework_module: self,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end

  def set_sane_defaults
    self.connection_timeout    ||= 30
    self.max_send_size         ||= 0
    self.send_delay            ||= 0

    # Don't use ||= with booleans
    self.send_lm                = true if self.send_lm.nil?
    self.send_ntlm              = true if self.send_ntlm.nil?
    self.send_spn               = true if self.send_spn.nil?
    self.use_lmkey              = false if self.use_lmkey.nil?
    self.use_ntlm2_session      = true if self.use_ntlm2_session.nil?
    self.use_ntlmv2             = true if self.use_ntlmv2.nil?
    self.auth                   = Msf::Exploit::Remote::AuthOption::AUTO if self.auth.nil?

    self.windows_authentication = datastore['USE_WINDOWS_AUTHENT']
    self.tdsencryption          = datastore['TDSENCRYPTION']
  end  
end
