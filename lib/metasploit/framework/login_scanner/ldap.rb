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

        attr_accessor :opts

        REALM_KEY = nil
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            status: Metasploit::Model::Login::Status::INCORRECT,
            proof: nil,
            host: host,
            port: port,
            protocol: 'ldap'
          }

          result_opts.merge!(do_login(credential))
          Result.new(result_opts)
        end

        def do_login(credential)
          opts = {
            username: credential.public,
            password: credential.private,
            framework_module: framework_module
          }.merge(@opts)

          connect_opts = ldap_connect_opts(host, port, connection_timeout, ssl: opts[:ssl], opts: opts)
          ldap_open(connect_opts) do |ldap|
            return status_code(ldap.get_operation_result.table)
          rescue StandardError => e
            { status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e }
          end
        end

        def status_code(operation_result)
          case operation_result[:code]
          when 0
            { status: Metasploit::Model::Login::Status::SUCCESSFUL }
          else
            { status: Metasploit::Model::Login::Status::INCORRECT, proof: "Bind Result: #{operation_result}" }
          end
        end

      end
    end
  end
end
