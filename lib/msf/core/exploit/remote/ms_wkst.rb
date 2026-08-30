###
#
# The Workstation Service Remote Protocol is used to perform tasks on a computer remotely on a
# network, including:
# 
# - Configuring properties and behavior of a Server Message Block network 
#   redirector (SMB network redirector).
# - Managing domain membership and computer names.
# - Gathering information, such as the number of enabled transport protocols and the number of
#   currently logged-on users.
#
# -*- coding: binary -*-

module Msf

  module Exploit::Remote::MsWkst

    include Msf::Exploit::Remote::SMB::Client::Ipc

    class MsWkstError < StandardError; end
    class MsWkstConnectionError < MsWkstError; end
    class MsWkstAuthenticationError < MsWkstError; end
    class MsWkstUnexpectedReplyError < MsWkstError; end

    WKS_UUID        = '6bffd098-a112-3610-9833-46c3f87e345a'.freeze
    WKS_VERS        = '1.0'.freeze
    WKSSVC_ENDPOINT = RubySMB::Dcerpc::Wkssvc.freeze

    # The currently connected WKSSVC pipe
    attr_reader :wkssvc_pipe

    def user_enum(level)
      self.wkssvc_pipe.netr_wksta_user_enum(
        level: level
      )
    end

    def get_info()
      self.wkssvc_pipe.netr_wksta_get_info
    end

    def disconnect_wkssvc
      begin
        self.wkssvc_pipe.close if self.wkssvc_pipe&.is_connected?
      rescue RubySMB::Error::UnexpectedStatusCode, RubySMB::Error::CommunicationError => e
        wlog e
      end
    end

    module_function

    def connect_wkssvc(tree)
      begin
        vprint_status('Connecting to Workstation Service Remote Protocol')
        self.wkssvc_pipe = tree.open_file(filename: 'wkssvc', write: true, read: true)

        raise MsWkstConnectionError.new('Could not open wkssvc pipe on remote SMB server.') unless wkssvc_pipe

        vprint_status('Binding to \\wkssvc...')
        self.wkssvc_pipe.bind(endpoint: WKSSVC_ENDPOINT)
        vprint_good('Bound to \\wkssvc')

        self.wkssvc_pipe
      rescue RubySMB::Dcerpc::Error::FaultError => e
        elog(e.message, error: e)
        raise MsWkstUnexpectedReplyError, "Connection failed (DCERPC fault: #{e.status_name})"
      end
    end

    protected

    attr_writer :wkssvc_pipe

  end

end
