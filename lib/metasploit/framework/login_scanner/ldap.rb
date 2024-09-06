# frozen_string_literal: true

require 'metasploit/framework/login_scanner/base'
require 'metasploit/framework/ldap/client'

module Metasploit
  module Framework
    module LoginScanner
      class LDAP
        include Metasploit::Framework::LoginScanner::Base
        include Metasploit::Framework::LDAP::Client
        include Msf::Exploit::Remote::LDAP

        LIKELY_PORTS         = [ 389, 636 ]
        LIKELY_SERVICE_NAMES = [ 'ldap', 'ldaps', 'ldapssl' ]

        attr_accessor :opts, :realm_key
        # @!attribute use_client_as_proof
        #   @return [Boolean] If a login is successful and this attribute is true - an LDAP::Client instance is used as proof
        attr_accessor :use_client_as_proof

        # This method sets the sane defaults for things
        # like timeouts and TCP evasion options
        def set_sane_defaults
          self.opts ||= {}
          self.connection_timeout = 30 if self.connection_timeout.nil?
          nil
        end

        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'tcp',
            service_name: 'ldap'
          }

          result_opts.merge!(do_login(credential))
          Result.new(result_opts)
        end

        def do_login(credential)
          opts = {
            username: credential.public,
            password: credential.private,
            framework_module: framework_module,
            ldap_auth: 'auto'
          }.merge(@opts)

          connect_opts = ldap_connect_opts(host, port, connection_timeout, ssl: opts[:ssl], opts: opts)
          begin
            ldap_client = ldap_open(connect_opts, keep_open: true)
            return status_code(ldap_client)
          rescue StandardError => e
            { status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end
        end

        def status_code(ldap_client)
          operation_result = ldap_client.get_operation_result.table[:code]
          case operation_result
          when 0
            result = { status: Metasploit::Model::Login::Status::SUCCESSFUL }
            if use_client_as_proof
              result[:proof] = ldap_client
              result[:connection] = ldap_client.socket
            end
            result
          else
            { status: Metasploit::Model::Login::Status::INCORRECT, proof: "Bind Result: #{operation_result}" }
          end
        end

        def each_credential
          cred_details.each do |raw_cred|
            # This could be a Credential object, or a Credential Core, or an Attempt object
            # so make sure that whatever it is, we end up with a Credential.
            credential = raw_cred.to_credential

            if opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::KERBEROS && opts[:ldap_krb5_cname]
              # If we're using kerberos auth with a ccache then the password is irrelevant
              # Remove it from the credential so we don't store it
              credential.private = nil
            elsif opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::SCHANNEL
              # If we're using kerberos auth with schannel then the user/password is irrelevant
              # Remove it from the credential so we don't store it
              credential.public = nil
              credential.private = nil
            end

            if credential.realm.present? && realm_key.present?
              credential.realm_key = realm_key
            elsif credential.realm.present? && realm_key.blank?
              # This service has no realm key, so the realm will be
              # meaningless. Strip it off.
              credential.realm = nil
              credential.realm_key = nil
            end

            yield credential

            if opts[:append_domain] && credential.realm.nil?
              credential.public = "#{credential.public}@#{opts[:domain]}"
              yield credential
            end
          end
        end
      end
    end
  end
end
