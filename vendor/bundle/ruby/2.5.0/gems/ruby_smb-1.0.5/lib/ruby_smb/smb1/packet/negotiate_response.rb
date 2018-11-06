module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NEGOTIATE Non-Extended Security Response Packet as defined in
      # [2.2.4.5.2.2 Non-Extended Security Response](https://msdn.microsoft.com/en-us/library/cc246327.aspx)
      class NegotiateResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE

        # An SMB_Parameters Block as defined by the {NegotiateResponse}.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16          :dialect_index, label: 'Dialect Index'
          security_mode   :security_mode
          uint16          :max_mpx_count,     label: 'Max Multiplex Count'
          uint16          :max_number_vcs,    label: 'Max Virtual Circuits'
          uint32          :max_buffer_size,   label: 'Max Buffer Size'
          uint32          :max_raw_size,      label: 'Max Raw Size'
          uint32          :session_key,       label: 'Session Key'
          capabilities    :capabilities
          file_time       :system_time,       label: 'Server System Time'
          int16           :server_time_zone,  label: 'Server TimeZone'
          uint8           :challenge_length,  label: 'Challenge Length', initial_value: 0x08
        end

        # An SMB_Data Block as defined by the {NegotiateResponse}
        class DataBlock < RubySMB::SMB1::DataBlock
          string        :challenge,     label: 'Auth Challenge', length: 8
          stringz16     :domain_name,   label: 'Primary Domain'
          stringz16     :server_name,   label: 'Server Name'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.flags.reply = 1
        end

        # Stores the list of {RubySMB::SMB1::Dialect} that were sent to the
        # peer/server in the related Negotiate Request. This will be used by
        # the {#negotiated_dialect} method.
        #
        # @param dialects [Array] array of {RubySMB::SMB1::Dialect}
        # @return dialects [Array] array of {RubySMB::SMB1::Dialect}
        # @raise [ArgumentError] if dialects is not an array of {RubySMB::SMB1::Dialect}
        def dialects=(dialects)
          unless dialects.all? { |dialect| dialect.is_a? Dialect }
            raise ArgumentError, 'Dialects must be an array of Dialect objects'
          end
          @dialects = dialects
        end

        # Returns the negotiated dialect identifier
        #
        # @return [String] the negotiated dialect identifier or an empty string if the list of {RubySMB::SMB1::Dialect} was not provided.
        def negotiated_dialect
          return '' if @dialects.nil? || @dialects.empty?
          @dialects[parameter_block.dialect_index].dialect_string
        end
      end
    end
  end
end
