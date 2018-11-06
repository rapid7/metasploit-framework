module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_SESSION_SETUP Response Packet as defined in
      # [2.2.4.6.2](https://msdn.microsoft.com/en-us/library/cc246329.aspx)
      class SessionSetupResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP

        # A SMB1 Parameter Block as defined by the {SessionSetupResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block   :andx_block
          uint16        :action,       label: 'Action'
          uint16        :security_blob_length, label: 'Security Blob Length'
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          string      :security_blob,  label: 'Security Blob (GSS-API)', length: -> { parent.parameter_block.security_blob_length }
          stringz     :native_os,      label: 'Native OS'
          stringz     :native_lan_man, label: 'Native LAN Manager'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end

        # Takes an NTLM Type 2 Message and creates the GSS Security Blob
        # for it and sets it in the {RubySMB::SMB1::Packet::SessionSetupRequest::DataBlock#security_blob}
        # field. It also automaticaly sets the length in
        # {RubySMB::SMB1::Packet::SessionSetupRequest::ParameterBlock#security_blob_length}
        #
        # @param type2_message [String] the serialized Type 2 NTLM message
        # @return [void]
        def set_type2_blob(type2_message)
          gss_blob = RubySMB::Gss.gss_type2(type2_message)
          data_block.security_blob = gss_blob
          parameter_block.security_blob_length = gss_blob.length
        end
      end
    end
  end
end
