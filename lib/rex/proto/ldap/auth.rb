require 'net/ldap'
require 'net/ldap/dn'

module Rex
  module Proto
    module LDAP
      class Auth
        SUPPORTS_SASL = %w[GSS-SPNEGO NTLM]
        NTLM_CONST = Rex::Proto::NTLM::Constants
        NTLM_CRYPT = Rex::Proto::NTLM::Crypt
        MESSAGE = Rex::Proto::NTLM::Message

        #
        # Initialize the required variables
        #
        # @param challenge [String] NTLM Server Challenge
        # @param domain    [String] Domain value used in NTLM
        # @param server    [String] Server value used in NTLM
        # @param dnsname   [String] DNS Name value used in NTLM
        # @param dnsdomain [String] DNS Domain value used in NTLM
        def initialize(challenge, domain, server, dnsname, dnsdomain)
          @domain = domain.nil? ? 'DOMAIN' : domain
          @server = server.nil? ? 'SERVER' : server
          @dnsname = dnsname.nil? ? 'server' : dnsname
          @dnsdomain = dnsdomain.nil? ? 'example.com' : dnsdomain
          @challenge = [challenge.nil? ? Rex::Text.rand_text_alphanumeric(16) : challenge].pack('H*')
        end

        #
        # Process the incoming LDAP login requests from clients
        #
        # @param user_login [OpenStruct] User login information
        #
        # @return auth_info [Hash] Processed authentication information
        def process_login_request(user_login)
          auth_info = {}

          if user_login.name.empty? && user_login.authentication.empty? # Anonymous
            auth_info = handle_anonymous_request(user_login, auth_info)
          elsif !user_login.name.empty? # Simple
            auth_info = handle_simple_request(user_login, auth_info)
          elsif sasl?(user_login)
            auth_info = handle_sasl_request(user_login, auth_info)
          else
            auth_info = handle_unknown_request(user_login, auth_info)
          end

          auth_info
        end

        #
        # Handle Anonymous authentication requests
        #
        # @param user_login [OpenStruct] User login information
        # @param auth_info [Hash] Processed authentication information
        #
        # @return auth_info [Hash] Processed authentication information
        def handle_anonymous_request(user_login, auth_info = {})
          if user_login.name.empty? && user_login.authentication.empty?
            auth_info[:user] = user_login.name
            auth_info[:pass] = user_login.authentication
            auth_info[:domain] = nil
            auth_info[:result_code] = Net::LDAP::ResultCodeSuccess
            auth_info[:auth_type] = 'Anonymous'
          end
          auth_info
        end

        #
        # Handle Unknown authentication requests
        #
        # @param user_login [OpenStruct] User login information
        # @param auth_info [Hash] Processed authentication information
        #
        # @return auth_info [Hash] Processed authentication information
        def handle_unknown_request(user_login, auth_info = {})
          auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported
          auth_info[:error_msg] = 'Invalid LDAP Login Attempt => Unknown Authentication Format'
          auth_info
        end

        #
        # Handle Simple authentication requests
        #
        # @param user_login [OpenStruct] User login information
        # @param auth_info [Hash] Processed authentication information
        #
        # @return auth_info [Hash] Processed authentication information
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
                auth_info[:error_msg] = "Invalid LDAP Login Attempt => DN:#{user_login.name}"
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
                auth_info[:user] = names.join('')
                auth_info[:domain] = domains.empty? ? nil : domains.join('.')
              rescue Net::LDAP::InvalidDNError => e
                auth_info[:error_msg] = "Invalid LDAP Login Attempt => DN:#{user_login.name}"
                raise e
              end
            elsif user_login.name =~ /\\/
              pub_info = user_login.name.split('\\')
              if pub_info.length <= 2
                auth_info[:domain], auth_info[:user] = pub_info
              else
                auth_info[:result_code] = Net::LDAP::ResultCodeInvalidCredentials
                auth_info[:error_msg] = "Invalid LDAP Login Attempt => DN:#{user_login.name}"
              end
            else
              auth_info[:user] = user_login.name
              auth_info[:domain] = nil
              auth_info[:result_code] = Net::LDAP::ResultCodeInvalidCredentials
            end
            auth_info[:private] = user_login.authentication
            auth_info[:private_type] = :password
            auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported if auth_info[:result_code].nil?
            auth_info[:auth_type] = 'Simple'
            auth_info
          end
        end

        #
        # Handle SASL authentication requests
        #
        # @param user_login [OpenStruct] User login information
        # @param auth_info [Hash] Processed authentication information
        #
        # @return auth_info [Hash] Processed authentication information
        def handle_sasl_request(user_login, auth_info = {})
          case user_login.authentication[1]
          when /NTLMSSP/
            message = Net::NTLM::Message.parse(user_login.authentication[1])
            if message.is_a?(::Net::NTLM::Message::Type1)
              auth_info[:server_creds] = generate_type2_response(message)
              auth_info[:result_code] = Net::LDAP::ResultCodeSaslBindInProgress
            elsif message.is_a?(::Net::NTLM::Message::Type3)
              auth_info = handle_type3_message(message, auth_info)
              auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported
            end
          else
            auth_info[:result_code] = Net::LDAP::ResultCodeAuthMethodNotSupported
            auth_info[:error_msg] = 'Invalid LDAP Login Attempt => Unsupported SASL Format'
          end
          auth_info[:auth_type] = 'SASL'
          auth_info
        end

        private

        #
        # Determine if the supplied request is formatted for SASL auth
        #
        # @param user_login [OpenStruct] User login information
        #
        # @return [bool] True if the request can be processed for SASL auth
        def sasl?(user_login)
          if user_login.authentication.is_a?(Array) && SUPPORTS_SASL.include?(user_login.authentication[0])
            return true
          end

          false
        end

        #
        # Generate NTLM Type2 response from NTLM Type1 message
        #
        # @param message [Net::NTLM::Message::Type1] NTLM Type1 message
        #
        # @return server_hash [String] NTLM Type2 response that is sent as server credentials
        def generate_type2_response(message)
          dom = message.domain
          ws = message.workstation
          domain = dom.empty? ? @domain : dom
          server = ws.empty? ? @server : ws
          server_hash = MESSAGE.process_type1_message(message.encode64, @challenge, domain, server, @dnsname, @dnsdomain)
          Rex::Text.decode_base64(server_hash)
        end

        #
        # Handle NTLM Type3 message
        #
        # @param message [Net::NTLM::Message::Type3] NTLM Type3 message
        # @param auth_info [Hash] Processed authentication information
        #
        # @return auth_info [Hash] Processed authentication information
        def handle_type3_message(message, auth_info = {})
          arg = {
            domain: message.domain,
            user: message.user,
            host: message.workstation
          }

          domain, user, host, lm_hash, ntlm_hash = MESSAGE.process_type3_message(message.encode64)
          nt_len = ntlm_hash.length

          if nt_len == 48
            arg[:ntlm_ver] = NTLM_CONST::NTLM_V1_RESPONSE
            arg[:lm_hash] = lm_hash
            arg[:nt_hash] = ntlm_hash

            if arg[:lm_hash][16, 32] == '0' * 32
              arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
            end
          elsif nt_len > 48
            arg[:ntlm_ver] = NTLM_CONST::NTLM_V2_RESPONSE
            arg[:lm_hash] = lm_hash[0, 32]
            arg[:lm_cli_challenge] = lm_hash[32, 16]
            arg[:nt_hash] = ntlm_hash[0, 32]
            arg[:nt_cli_challenge] = ntlm_hash[32, nt_len - 32]
          else
            auth_info[:error_msg] = "Unknown hash type from #{host}, ignoring ..."
          end
          auth_info.merge(process_ntlm_hash(arg)) unless arg.nil?
        end

        #
        # Process the NTLM Hash received from NTLM Type3 message
        #
        # @param arg [Hash] authentication information received from Type3 message
        #
        # @return arg [Hash] Processed NTLM authentication information
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
          host = Rex::Text.to_ascii(arg[:host])

          case ntlm_ver
          when NTLM_CONST::NTLM_V1_RESPONSE
            if NTLM_CRYPT.is_hash_from_empty_pwd?({
              hash: [nt_hash].pack('H*'),
              srv_challenge: @challenge,
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
              srv_challenge: @challenge,
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
            ].join(':').gsub("\n", '\\n')
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
              arg[:error_msg] = 'NTLMv2 Hash correspond to an empty password, ignoring ... '
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

            hash = [
              lm_hash || '0' * 32,
              nt_hash || '0' * 32
            ].join(':').gsub("\n", '\\n')
            arg[:private] = hash
          when NTLM_CONST::NTLM_2_SESSION_RESPONSE
            if NTLM_CRYPT.is_hash_from_empty_pwd?({
              hash: [nt_hash].pack('H*'),
              srv_challenge: @challenge,
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
            ].join(':').gsub("\n", '\\n')
            arg[:private] = hash
          else
            return
          end
          arg[:domain] = domain
          arg[:user] = user
          arg[:host] = host
          arg[:private_type] = :ntlm_hash
          arg
        end
      end
    end
  end
end
