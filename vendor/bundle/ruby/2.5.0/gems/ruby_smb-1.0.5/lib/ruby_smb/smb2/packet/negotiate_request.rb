module RubySMB
  module SMB2
    module Packet
      # An SMB2 NEGOTIATE Request packet as defined by
      # [2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
      class NegotiateRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::NEGOTIATE

        endian              :little
        smb2_header         :smb2_header
        uint16              :structure_size,      label: 'Structure Size', initial_value: 36
        uint16              :dialect_count,       label: 'Dialect Count'
        smb2_security_mode  :security_mode
        uint16              :reserved1, label: 'Reserved', initial_value: 0
        smb2_capabilities   :capabilities
        string              :client_guid,         label: 'Client GUID',        length: 16
        file_time           :client_start_time,   label: 'Client Start Time',  initial_value: 0
        array               :dialects,            label: 'Dialects',           type: :uint16, read_until: :eof

        # Adds a dialect to the Dialects array and increments the dialect count
        #
        # @param [Fixnum] the numeric code for the dialect you wish to add
        # @return [Array<Fixnum>] the array of all currently selected dialects
        def add_dialect(dialect)
          return ArgumentError, 'Must be a number' unless dialect.is_a? Integer
          self.dialect_count += 1
          dialects << dialect
        end

        # Takes an array of dialects and sets it on the packet. Also updates
        # the dialect_count field appropriately. Will erase any previously set
        # dialects.
        #
        # @param [Array<Fixnum>] the array of dialects to set
        # @return [Array<Fixnum>] the current value of the dialects array
        def set_dialects(add_dialects = [])
          self.dialects = []
          self.dialect_count = 0
          add_dialects.each do |dialect|
            add_dialect(dialect)
          end
          dialects
        end
      end
    end
  end
end
