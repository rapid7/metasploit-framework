require 'net/ldap'
require 'net/ldap/dn'

module Rex
  module Proto
    module LDAP
      module Server
        class Auth
          NTLM_CONST = Rex::Proto::NTLM::Constants
          NTLM_CRYPT = Rex::Proto::NTLM::Crypt
          MESSAGE = Rex::Proto::NTLM::Message

          def process_login_request(user_login)
            auth_info = {}

            if user_login.name.empty? && user_login.authentication.empty? # Anonymous
              auth_info = handle_anonymous_request(user_login, auth_info)
            elsif !user_login.name.empty? # Simple
              auth_info = handle_simple_request(user_login, auth_info)
            elsif user_login.authentication[0] == 'GSS-SPNEGO' # SASL especially SPNEGO
              auth_info = handle_sasl_request(user_login, auth_info)
            else
              auth_info[:result_code] = Net::LDAP::ResultCodeUnwillingToPerform
            end

            auth_info
          end

          def handle_anonymous_request(user_login, auth_info = {})
            if user_login.name.empty? && user_login.authentication.empty?
              auth_info[:user] = user_login.name
              auth_info[:pass] = user_login.authentication
              auth_info[:domain] = nil
              auth_info[:result_code] = Net::LDAP::ResultCodeSuccess
              auth_info[:auth_type] = 'Anonymous'

              auth_info # think about the else ccondition
            end
          end

          def handle_simple_request(user_login, auth_info = {})
            domains = []
            names = []
            if !user_login.name.empty?
              if user_login.name =~ /@/
                pub_info = user_login.name.split('@')
                if pub_info.length <= 2
                  auth_info[:user], auth_info[:domain] = pub_info
                else
                  auth_info[:result_code] = Net::LDAP::ResultCodeInvalidCredentials
                  auth_info[:result_message] = "LDAP Login Attempt => From:#{auth_info[:name]} DN:#{user_login.name}"
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
                  auth_info[:user] = names.first
                  auth_info[:domain] = domains.empty? ? nil : domains.join('.')
                rescue InvalidDNError => e
                  auth_info[:result_message] = "LDAP Login Attempt => From:#{auth_info[:name]} DN:#{user_login.name}"
                  raise e
                end
              elsif user_login.name =~ /\\/
                pub_info = user_login.name.split('\\')
                if pub_info.length <= 2
                  auth_info[:domain], auth_info[:user] = pub_info
                else
                  auth_info[:result_code] = Net::LDAP::ResultCodeInvalidCredentials
                  auth_info[:result_message] = "LDAP Login Attempt => From:#{auth_info[:name]} DN:#{user_login.name}"
                end
              else
                auth_info[:user] = user_login.name
                auth_info[:domain] = nil
                auth_info[:result_code] = Net::LDAP::ResultCodeInvalidCredentials
              end
              auth_info[:private] = user_login.authentication
              auth_info[:private_type] = :password
              auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported if auth_info[:result_code].nil?
              auth_info[:auth_info] = 'Simple'
              auth_info
            end
          end

          def handle_sasl_request(user_login, auth_info = {})
            if user_login.authentication[1] =~ /NTLMSSP/
              message = user_login.authentication[1]

              if message[8, 1] == "\x01"
                auth_info[:ntlm_t2] = generate_type2_response
                auth_info[:result_code] = Net::LDAP::ResultCodeSaslBindInProgress
              elsif message[8, 1] == "\x03"
                auth_info = handle_type3_message(message, auth_info)
                auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported
              end
            end
            auth_info[:auth_type] = 'SASL'
            auth_info
          end

          def generate_type2_response
            domain = datastore['Domain']
            server = datastore['Server'] # parse the domain and everythingfrom the type 1 received
            dnsname = datastore['DnsName']
            dnsdomain = datastore['DnsDomain']
            challenge = [ datastore['CHALLENGE'] ].pack('H*')
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
            chalhash
          end

          def handle_type3_message(message, auth_info = {})
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
              auth_info[:error_msg] = "Empty hash from #{host} captured, ignoring ... "
            else
              auth_info[:error_msg] = "Unknown hash type from #{host}, ignoring ..."
            end
            unless arg.nil?
              arg[:user] = user
              arg[:domain] = domain
              arg[:host] = host
              arg = process_ntlm_hash(arg)
              auth_info = auth_info.merge(arg)
            end
            auth_info
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
            host = arg[:host]
            challenge = [datastore['CHALLENGE'].pack('H*')]

            case ntlm_ver
            when NTLM_CONST::NTLM_V1_RESPONSE
              if NTLM_CRYPT.is_hash_from_empty_pwd?({
                  hash: [nt_hash].pack('H*'),
                  srv_challenge: challenge,
                  ntlm_ver: NTLM_CONST::NTLM_V1_RESPONSE,
                  type: 'ntlm'
                })
                arg[:error_msg] = 'NLMv1 Hash correspond to an empty password, ignoring ... '
                return
              end
              if lm_hash == nt_hash || lm_hash == '' || lm_hash =~ /^0*$/
                lm_hash_message = 'Disabled'
              elsif NTLM_CRYPT.is_hash_from_empty_pwd?({
                  hash: [lm_hash].pack('H*'),
                  srv_challenge: challenge,
                  ntlm_ver: NTLM_CONST::NTLM_V1_RESPONSE,
                  type: 'lm'
                })
                lm_hash_message = 'Disabled (from empty password)'
              else
                lm_hash_message = lm_hash
              end

              hash = [
                  lm_hash || '0' * 48,
                  nt_hash || '0' * 48
              ].join(':').gsub(/\n/, '\\n')
              arg[:private] = hash
            when NTLM_CONST::NTLM_V2_RESPONSE
              if NTLM_CRYPT.is_hash_from_empty_pwd?({
                  hash: [nt_hash].pack('H*'),
                  srv_challenge: challenge,
                  cli_challenge: [nt_cli_challenge].pack('H*'),
                  user: user,
                  domain: domain,
                  ntlm_ver: NTLM_CONST::NTLM_V2_RESPONSE,
                  type: 'ntlm'
                })
                arg[:error_msg] = 'NTLMv2 Hash correspond to an empty password, ignoring ... '
                return
              end
              if (lm_hash == '0' * 32) && (lm_cli_challenge == '0' * 16)
                lm_hash_message = 'Disabled'
              elsif NTLM_CRYPT.is_hash_from_empty_pwd?({
                  hash: [lm_hash].pack('H*'),
                  srv_challenge: challenge,
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

              hash = [
                  lm_hash || '0' * 32,
                  nt_hash || '0' * 32
              ].join(':').gsub(/\n/, '\\n')
              arg[:private] = hash
            when NTLM_CONST::NTLM_2_SESSION_RESPONSE
              if NTLM_CRYPT.is_hash_from_empty_pwd?({
                  hash: [nt_hash].pack('H*'),
                  srv_challenge: challenge,
                  cli_challenge: [lm_hash].pack('H*')[0, 8],
                  ntlm_ver: NTLM_CONST::NTLM_2_SESSION_RESPONSE,
                  type: 'ntlm'
                })
                arg[:error_msg] = 'NTLM2_session Hash correspond to an empty password, ignoring ... '
                return
              end

              hash = [
                  lm_hash || '0' * 48,
                  nt_hash || '0' * 48
              ].join(':').gsub(/\n/, '\\n')
              arg[:private] = hash
            else
                return
            end
            arg[:domain] = domain
            arg[:user] = user
            arg[:private_type] = :ntlm_hash
            arg
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
      end
    end
  end
end