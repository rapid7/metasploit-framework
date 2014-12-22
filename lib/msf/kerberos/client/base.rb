# -*- coding: binary -*-

module Msf
  module Kerberos
    module Client
      module Base

        # Builds a kerberos Client Name Principal
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :client_name the client's name
        # @option opts [Fixnum] :client_type the client's name type
        # @return [Rex::Proto::Kerberos::Model::PrincipalName]
        # @see Rex::Proto::Kerberos::Model::PrincipalName
        def build_client_name(opts = {})
          name = opts[:client_name] || ''
          name_type = opts[:client_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

          Rex::Proto::Kerberos::Model::PrincipalName.new(
            name_type: name_type,
            name_string: name.split('/')
          )
        end

        # Builds a kerberos Server Name Principal
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :server_name the server's name
        # @option opts [Fixnum] :server_type the server's name type
        # @return [Rex::Proto::Kerberos::Model::PrincipalName]
        # @see Rex::Proto::Kerberos::Model::PrincipalName
        def build_server_name(opts = {})
          name = opts[:server_name] || ''
          name_type = opts[:server_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

          Rex::Proto::Kerberos::Model::PrincipalName.new(
            name_type: name_type,
            name_string: name.split('/')
          )
        end
      end
    end
  end
end
