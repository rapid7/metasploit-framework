# -*- coding: binary -*-

module Msf
  module Kerberos
    module Microsoft
      module Client
        module Base
          # Builds a kerberos Client Name Principal
          #
          # @param opts [Hash{Symbol => <String, Fixnum>}]
          # @option opts [String] :cname
          # @option opts [Fixnum] :cname_type
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def build_client_name(opts = {})
            name = opts[:cname] || ''
            name_type = opts[:cname_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

            Rex::Proto::Kerberos::Model::PrincipalName.new(
                name_type: name_type,
                name_string: name.split('/')
            )
          end

          # Builds a kerberos Server Name Principal
          #
          # @param opts [Hash{Symbol => <String, Fixnum>}]
          # @option opts [String] :sname the name
          # @option opts [Fixnum] :sname_type the name type
          # @return [Rex::Proto::Kerberos::Model::PrincipalName]
          def build_server_name(opts = {})
            name = opts[:sname] || ''
            name_type = opts[:sname_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

            Rex::Proto::Kerberos::Model::PrincipalName.new(
                name_type: name_type,
                name_string: name.split('/')
            )
          end

          # Builds a kerberos PA-PAC-REQUEST pre authenticated structure
          #
          # @param opts [Hash{Symbol => Boolean}]
          # @option opts [Boolean] :pac_request_value
          # @return [Rex::Proto::Kerberos::Model::Field::PreAuthData]
          def build_pa_pac_request(opts = {})
            value = opts[:pac_request_value] || false
            pac_request = Rex::Proto::Kerberos::Model::PreAuthPacRequest.new(value: value)
            pa_pac_request = Rex::Proto::Kerberos::Model::PreAuthData.new(
                type: Rex::Proto::Kerberos::Model::PA_PAC_REQUEST,
                value: pac_request.encode
            )

            pa_pac_request
          end
        end
      end
    end
  end
end
