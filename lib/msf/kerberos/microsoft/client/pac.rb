# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Microsoft
      module Client
        module Pac
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

          def build_pac(opts)
            user_name = opts[:client_name] || ''
            user_id = opts[:user_id] || 1000
            primary_group_id = opts[:group_id] || 513
            group_ids = opts[:group_ids] || [513]
            domain_name = opts[:realm] || ''
            domain_id = opts[:domain_id] || ''
            logon_time = opts[:logon_time]
            if logon_time.nil?
              raise ::RuntimeError, 'logon_time not set on build pac'
            end
            checksum_type = opts[:checksum_type] || Rex::Proto::Kerberos::Crypto::RsaMd5::RSA_MD5

            logon_info = Rex::Proto::Kerberos::Pac::LogonInfo.new(
                logon_time: logon_time,
                effective_name: user_name,
                user_id: user_id,
                primary_group_id: primary_group_id,
                group_ids: group_ids,
                logon_domain_name: domain_name,
                logon_domain_id: domain_id,
            )

            client_info = Rex::Proto::Kerberos::Pac::ClientInfo.new(
                client_id: logon_time,
                name: user_name
            )

            server_checksum = Rex::Proto::Kerberos::Pac::ServerChecksum.new(
                checksum: checksum_type
            )

            priv_srv_checksum = Rex::Proto::Kerberos::Pac::PrivSvrChecksum.new(
                checksum: checksum_type
            )

            pac_type = Rex::Proto::Kerberos::Pac::Type.new(
                buffers: [
                             logon_info,
                             client_info,
                             server_checksum,
                             priv_srv_checksum
                         ],
                checksum: checksum_type
            )

            pac_type
          end
        end
      end
    end
  end
end
