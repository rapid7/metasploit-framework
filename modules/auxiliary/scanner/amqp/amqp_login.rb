##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/amqp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Creates an instance of this module.
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'AMQP 0-9-1 Login Check Scanner',
        'Description' => %q{
          This module will test AMQP logins on a range of machines and
          report successful logins.  If you have loaded a database plugin
          and connected to a database this module will record successful
          logins and hosts so you can track your access.
        },
        'Author' => [ 'Spencer McIntyre' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://www.rabbitmq.com/amqp-0-9-1-reference.html' ]
        ],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(5671)
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SSL', [ true, 'Negotiate SSL/TLS for outgoing connections', true ]),
        Opt::SSLVersion
      ]
    )
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::AMQP.new(
      host: ip,
      port: datastore['RPORT'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      framework: framework,
      framework_module: self,
      ssl: datastore['SSL'],
      ssl_version: datastore['SSLVersion']
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

        print_good "#{ip}:#{datastore['RPORT']} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{datastore['RPORT']} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
