module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_SESSION_SETUP_ANDX Request Packet, without NTLMSSP as defined in
      # [2.2.4.53.1 Request](https://msdn.microsoft.com/en-us/library/ee441849.aspx)
      class SessionSetupLegacyRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP

        # A SMB1 Parameter Block as defined by the {SessionSetupRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block   :andx_block
          uint16        :max_buffer_size,         label: 'Max Buffer Size'
          uint16        :max_mpx_count,           label: 'Max Mpx Count'
          uint16        :vc_number,               label: 'VC Number'
          uint32        :session_key,             label: 'Session Key'
          uint16        :oem_password_length,     label: 'OEM Password Length',       initial_value: -> { parent.data_block.oem_password.length }
          uint16        :unicode_password_length, label: 'Unicored Password Length',  initial_value: -> { parent.data_block.unicode_password.length }
          uint32        :reserved
          capabilities  :capabilities
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupRequest} Packet.
        # Due to vagaries of character encoding and the way we currently handle NTLM authentication
        # for the security blob, you must null-terminate the {native_os} and {native_lan_man} fields
        # yourself if you set them away from their defaults.
        class DataBlock < RubySMB::SMB1::DataBlock
          string      :oem_password,      label: 'OEM Password'
          string      :unicode_password,  label: 'Unicode password'
          string      :padding,           label: 'Padding'
          string      :account_name,      label: 'Account Name(username)',  length: 2
          string      :primary_domain,    label: 'Primary Domain',          length: 2
          stringz     :native_os,         label: 'Native OS',               initial_value: 'Windows 7 Ultimate N 7601 Service Pack 1'
          stringz     :native_lan_man,    label: 'Native LAN Manager',      initial_value: 'Windows 7 Ultimate N 6.1'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          parameter_block.capabilities.extended_security = 0
        end
      end
    end
  end
end
