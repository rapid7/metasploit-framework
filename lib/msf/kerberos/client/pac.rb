# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
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

        # Builds a kerberos PACTYPE structure
        #
        # @param opts [Hash{Symbol => <String, Fixnum, Array, Time>}]
        # @option opts [String] :client_name
        # @option opts [Fixnum] :user_id the user SID Ex: 1000
        # @option opts [Fixnum] :group_id Ex: 513 for 'Domain Users'
        # @option opts [Array<Fixnum>] :group_ids
        # @option opts [String] :realm
        # @option opts [String] :domain_id the domain SID Ex: S-1-5-21-1755879683-3641577184-3486455962
        # @option opts [Time] :logon_time
        # @return [Rex::Proto::Kerberos::Pac::Type]
        def build_pac(opts)
          user_name = opts[:client_name] || ''
          user_id = opts[:user_id] || 1000
          primary_group_id = opts[:group_id] || 513
          group_ids = opts[:group_ids] || [513]
          domain_name = opts[:realm] || ''
          domain_id = opts[:domain_id] || ''
          logon_time = opts[:logon_time] || Time.now

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

        # Builds an kerberos AuthorizationData structure containing a PACTYPE
        #
        # @param opts [Hash{Symbol => String}]
        # @option opts [String] :pac
        # @return [Rex::Proto::Kerberos::Model::AuthorizationData]
        def build_pac_authorization_data(opts)
          pac = opts[:pac] || ''

          pac_auth_data = Rex::Proto::Kerberos::Model::AuthorizationData.new(
            elements: [{:type => Rex::Proto::Kerberos::Pac::AD_WIN2K_PAC, :data => pac}]
          )
          authorization_data = Rex::Proto::Kerberos::Model::AuthorizationData.new(
            elements: [{:type => Rex::Proto::Kerberos::Model::AD_IF_RELEVANT, :data => pac_auth_data.encode}]
          )

          authorization_data
        end

      end
    end
  end
end
