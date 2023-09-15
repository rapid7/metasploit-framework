# frozen_string_literal: true

module Metasploit
  module Framework
    module LDAP

      module Client
        def ldap_connect_opts(rhost, rport, connect_timeout, ssl: true, opts: {})
          connect_opts = {
            host: rhost,
            port: rport,
            connect_timeout: connect_timeout,
            proxies: opts[:proxies]
          }

          if ssl
            connect_opts[:encryption] = {
              method: :simple_tls,
              tls_options: {
                verify_mode: OpenSSL::SSL::VERIFY_NONE
              }
            }
          end

          case opts[:ldap_auth]
          when Msf::Exploit::Remote::AuthOption::SCHANNEL
            pfx_path = opts[:ldap_cert_file]
            raise Msf::ValidationError, 'The LDAP::CertFile option is required when using SCHANNEL authentication.' if pfx_path.blank?
            raise Msf::ValidationError, 'The SSL option must be enabled when using SCHANNEL authentication.' if ssl != true

            unless ::File.file?(pfx_path) && ::File.readable?(pfx_path)
              raise Msf::ValidationError, 'Failed to load the PFX certificate file. The path was not a readable file.'
            end

            begin
              pkcs = OpenSSL::PKCS12.new(File.binread(pfx_path), '')
            rescue StandardError => e
              raise Msf::ValidationError, "Failed to load the PFX file (#{e})"
            end

            connect_opts[:auth] = {
              method: :sasl,
              mechanism: 'EXTERNAL',
              initial_credential: '',
              challenge_response: true
            }
            connect_opts[:encryption] = {
              method: :start_tls,
              tls_options: {
                verify_mode: OpenSSL::SSL::VERIFY_NONE,
                cert: pkcs.certificate,
                key: pkcs.key
              }
            }
          when Msf::Exploit::Remote::AuthOption::KERBEROS
            raise Msf::ValidationError, 'The Ldap::Rhostname option is required when using Kerberos authentication.' if opts[:ldap_rhostname].blank?
            raise Msf::ValidationError, 'The DOMAIN option is required when using Kerberos authentication.' if opts[:domain].blank?
            raise Msf::ValidationError, 'The DomainControllerRhost is required when using Kerberos authentication.' if opts[:domain_controller_rhost].blank?

            offered_etypes = Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(opts[:ldap_krb_offered_enc_types])
            raise Msf::ValidationError, 'At least one encryption type is required when using Kerberos authentication.' if offered_etypes.empty?

            kerberos_authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::LDAP.new(
              host: opts[:domain_controller_rhost],
              hostname: opts[:ldap_rhostname],
              realm: opts[:domain],
              username: opts[:username],
              password: opts[:password],
              framework: opts[:framework],
              framework_module: opts[:framework_module],
              cache_file: opts[:ldap_krb5_cname].blank? ? nil : opts[:ldap_krb5_cname],
              ticket_storage: opts[:kerberos_ticket_storage],
              offered_etypes: offered_etypes
            )

            connect_opts[:auth] = {
              method: :sasl,
              mechanism: 'GSS-SPNEGO',
              initial_credential: proc do
                kerberos_result = kerberos_authenticator.authenticate
                kerberos_result[:security_blob]
              end,
              challenge_response: true
            }
          when Msf::Exploit::Remote::AuthOption::NTLM
            ntlm_client = RubySMB::NTLM::Client.new(
              opts[:username],
              opts[:password],
              workstation: 'WORKSTATION',
              domain: opts[:domain].blank? ? '.' : opts[:domain],
              flags:
                RubySMB::NTLM::NEGOTIATE_FLAGS[:UNICODE] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:REQUEST_TARGET] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:NTLM] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:ALWAYS_SIGN] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY_EXCHANGE] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:TARGET_INFO] |
                  RubySMB::NTLM::NEGOTIATE_FLAGS[:VERSION_INFO]
            )

            negotiate = proc do |challenge|
              ntlmssp_offset = challenge.index('NTLMSSP')
              type2_blob = challenge.slice(ntlmssp_offset..-1)
              challenge = [type2_blob].pack('m')
              type3_message = ntlm_client.init_context(challenge)
              type3_message.serialize
            end

            connect_opts[:auth] = {
              method: :sasl,
              mechanism: 'GSS-SPNEGO',
              initial_credential: ntlm_client.init_context.serialize,
              challenge_response: negotiate
            }
          when Msf::Exploit::Remote::AuthOption::PLAINTEXT
            connect_opts[:auth] = {
              method: :simple,
              username: opts[:username],
              password: opts[:password]
            }
          when Msf::Exploit::Remote::AuthOption::AUTO
            unless opts[:username].blank? # plaintext if specified
              connect_opts[:auth] = {
                method: :simple,
                username: opts[:username],
                password: opts[:password]
              }
            end
          end

          connect_opts
        end
      end
    end
  end
end
