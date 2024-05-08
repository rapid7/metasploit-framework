# frozen_string_literal: true

require 'metasploit/framework/ldap/ntlm_encryptor'
require 'metasploit/framework/ldap/spnego_kerberos_encryptor'

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
            connect_opts.merge!(ldap_auth_opts_schannel(opts, ssl))
          when Msf::Exploit::Remote::AuthOption::KERBEROS
            connect_opts.merge!(ldap_auth_opts_kerberos(opts, ssl))
          when Msf::Exploit::Remote::AuthOption::NTLM
            connect_opts.merge!(ldap_auth_opts_ntlm(opts, ssl))
          when Msf::Exploit::Remote::AuthOption::PLAINTEXT
            connect_opts.merge!(ldap_auth_opts_plaintext(opts))
          when Msf::Exploit::Remote::AuthOption::AUTO
            if opts[:username].present? && opts[:domain].present?
              connect_opts.merge!(ldap_auth_opts_ntlm(opts, ssl))
            elsif opts[:username].present?
              connect_opts.merge!(ldap_auth_opts_plaintext(opts))
            end
          end

          connect_opts
        end

        private

        def ldap_auth_opts_kerberos(opts, ssl)
          auth_opts = {}
          raise Msf::ValidationError, 'The LDAP::Rhostname option is required when using Kerberos authentication.' if opts[:ldap_rhostname].blank?
          raise Msf::ValidationError, 'The DOMAIN option is required when using Kerberos authentication.' if opts[:domain].blank?

          offered_etypes = Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(opts[:ldap_krb_offered_enc_types])
          raise Msf::ValidationError, 'At least one encryption type is required when using Kerberos authentication.' if offered_etypes.empty?

          sign_and_seal = opts.fetch(:sign_and_seal, !ssl)
          kerberos_authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::LDAP.new(
            host: opts[:domain_controller_rhost].blank? ? nil : opts[:domain_controller_rhost],
            hostname: opts[:ldap_rhostname],
            realm: opts[:domain],
            username: opts[:username],
            password: opts[:password],
            framework: opts[:framework],
            framework_module: opts[:framework_module],
            cache_file: opts[:ldap_krb5_cname].blank? ? nil : opts[:ldap_krb5_cname],
            ticket_storage: opts[:kerberos_ticket_storage],
            offered_etypes: offered_etypes,
            mutual_auth: true,
            use_gss_checksum: sign_and_seal
          )

          encryptor = SpnegoKerberosEncryptor.new(kerberos_authenticator)

          auth_opts[:auth] = {
            method: :sasl,
            mechanism: 'GSS-SPNEGO',
            initial_credential: proc do
              encryptor.get_initial_credential
            end,
            challenge_response: true
          }

          if sign_and_seal
            auth_opts[:auth][:auth_context_setup] = encryptor.method(:kerberos_setup)
          end

          auth_opts
        end

        def ldap_auth_opts_ntlm(opts, ssl)
          auth_opts = {}
          flags = RubySMB::NTLM::NEGOTIATE_FLAGS[:UNICODE] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:REQUEST_TARGET] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:NTLM] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:ALWAYS_SIGN] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY_EXCHANGE] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:TARGET_INFO] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:VERSION_INFO]

          sign_and_seal = opts.fetch(:sign_and_seal, !ssl)
          if sign_and_seal
            flags = flags |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:SIGN] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:SEAL] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY128] |
                RubySMB::NTLM::NEGOTIATE_FLAGS[:KEY56]
          end
          ntlm_client = RubySMB::NTLM::Client.new(
            (opts[:username].nil? ? '' : opts[:username]),
            (opts[:password].nil? ? '' : opts[:password]),
            workstation: 'WORKSTATION',
            domain: opts[:domain].blank? ? '.' : opts[:domain],
            flags: flags
          )

          negotiate = proc do |challenge|
            ntlmssp_offset = challenge.index('NTLMSSP')
            type2_blob = challenge.slice(ntlmssp_offset..-1)
            challenge = [type2_blob].pack('m')
            type3_message = ntlm_client.init_context(challenge)
            type3_message.serialize
          end

          encryptor = NtlmEncryptor.new(ntlm_client)

          auth_opts[:auth] = {
            method: :sasl,
            mechanism: 'GSS-SPNEGO',
            initial_credential: ntlm_client.init_context.serialize,
            challenge_response: negotiate
          }

          if sign_and_seal
            auth_opts[:auth][:auth_context_setup] = encryptor.method(:ntlm_setup)
          end

          auth_opts
        end

        def ldap_auth_opts_plaintext(opts)
          auth_opts = {}
          raise Msf::ValidationError, 'Can not sign and seal when using Plaintext authentication.' if opts.fetch(:sign_and_seal, false)

          auth_opts[:auth] = {
            method: :simple,
            username: opts[:username],
            password: opts[:password]
          }
          auth_opts
        end

        def ldap_auth_opts_schannel(opts, ssl)
          auth_opts = {}
          pfx_path = opts[:ldap_cert_file]
          raise Msf::ValidationError, 'The SSL option must be enabled when using Schannel authentication.' unless ssl
          raise Msf::ValidationError, 'The LDAP::CertFile option is required when using Schannel authentication.' if pfx_path.blank?
          raise Msf::ValidationError, 'Can not sign and seal when using Schannel authentication.' if opts.fetch(:sign_and_seal, false)

          unless ::File.file?(pfx_path) && ::File.readable?(pfx_path)
            raise Msf::ValidationError, 'Failed to load the PFX certificate file. The path was not a readable file.'
          end

          begin
            pkcs = OpenSSL::PKCS12.new(File.binread(pfx_path), '')
          rescue StandardError => e
            raise Msf::ValidationError, "Failed to load the PFX file (#{e})"
          end

          auth_opts[:auth] = {
            method: :sasl,
            mechanism: 'EXTERNAL',
            initial_credential: '',
            challenge_response: true
          }
          auth_opts[:encryption] = {
            method: :start_tls,
            tls_options: {
              verify_mode: OpenSSL::SSL::VERIFY_NONE,
              cert: pkcs.certificate,
              key: pkcs.key
            }
          }
          auth_opts
        end
      end
    end
  end
end
