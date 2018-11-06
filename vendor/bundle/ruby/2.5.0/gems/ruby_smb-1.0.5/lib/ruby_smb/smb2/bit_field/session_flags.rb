module RubySMB
  module SMB2
    module BitField
      # The SessionsFlags bit-field for a {RubySMB::SMB2::Packet::SessionSetupResponse}
      class SessionFlags < BinData::Record
        endian  :little
        bit6    :reserved3,           label: 'Reserved', initial_value: 0
        bit1    :null,                label: 'ASYNC Command', initial_value: 0
        bit1    :guest,               label: 'Is Guest?',     initial_value: 0
        resume_byte_alignment
        # byte border
        uint8 :reserved1, label: 'Reserved', initial_value: 0
      end
    end
  end
end
