###
#
# This mixin provides methods to open, and close policy handles, and to query policy info on the remote SMB server.
#
# -*- coding: binary -*-

module Msf

  module Exploit::Remote::MsLsad

    include Msf::Exploit::Remote::SMB::Client::Ipc

    class MsLsadError < StandardError; end
    class MsLsadConnectionError < MsLsadError; end
    class MsLsadAuthenticationError < MsLsadError; end
    class MsLsadUnexpectedReplyError < MsLsadError; end

    LSA_UUID        = '12345778-1234-abcd-ef00-0123456789ab'.freeze
    LSA_VERS        = '0.0'.freeze
    LSARPC_ENDPOINT = RubySMB::Dcerpc::Lsarpc.freeze

    # The currently connected LSARPC pipe
    attr_reader :lsarpc_pipe

    def map_security_principal_to_string(security_principal)
      case security_principal
      when 1
        'User'
      when 2
        'Group'
      when 3
        'Domain'
      when 4
        'Alias'
      when 5
        'Well-Known Group'
      when 6
        'Deleted Account'
      when 7
        'Invalid'
      when 8
        'Unknown'
      when '9'
        'Computer'
      when 10
        'Label'
      else
        'Unknown - Not a valid Security Principal'
      end
    end

    def open_policy2(impersonation_level, security_context_tracking_mode, access_mask)
      self.lsarpc_pipe.lsar_open_policy2(
        system_name: simple.peerhost,
        object_attributes: {
          security_quality_of_service: {
            impersonation_level: impersonation_level,
            security_context_tracking_mode: security_context_tracking_mode
          }
        },
        access_mask: access_mask
      )
    end

    def query_information_policy(policy_handle, information_class)
      self.lsarpc_pipe.lsar_query_information_policy(
        policy_handle: policy_handle,
        information_class: information_class
      )
    end

    def close_policy(policy_handle)
      self.lsarpc_pipe.lsar_close_handle(
        policy_handle: policy_handle
      ) if (self.lsarpc_pipe && policy_handle)
    end

    def disconnect_lsarpc
      begin
        self.lsarpc_pipe.close if self.lsarpc_pipe&.is_connected?
      rescue RubySMB::Error::UnexpectedStatusCode, RubySMB::Error::CommunicationError => e
        wlog e
      end
    end

    module_function

    def connect_lsarpc(tree)
      begin
        vprint_status('Connecting to Local Security Authority (LSA) Remote Protocol')
        self.lsarpc_pipe = tree.open_file(filename: 'lsarpc', write: true, read: true)

        raise MsLsadConnectionError.new('Could not open lsarpc pipe on remote SMB server.') unless lsarpc_pipe

        vprint_status('Binding to \\lsarpc...')
        self.lsarpc_pipe.bind(endpoint: LSARPC_ENDPOINT)
        vprint_good('Bound to \\lsarpc')

        self.lsarpc_pipe
      rescue RubySMB::Dcerpc::Error::FaultError => e
        elog(e.message, error: e)
        raise MsLsadUnexpectedReplyError, "Connection failed (DCERPC fault: #{e.status_name})"
      end
    end

    protected

    attr_writer :lsarpc_pipe

  end

end
