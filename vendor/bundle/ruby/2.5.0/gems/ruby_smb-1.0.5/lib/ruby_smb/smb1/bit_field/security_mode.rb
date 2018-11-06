module RubySMB
  module SMB1
    module BitField
      # The SecurityMode bit-field for a NegotiateResponse as defined in
      # [2.2.4.52.2 Response](https://msdn.microsoft.com/en-us/library/ee441946.aspx)
      class SecurityMode < BinData::Record
        endian :little
        bit4    :reserved,                      label: 'Reserved'
        bit1    :security_signatures_required,  label: 'Signatures Required'
        bit1    :security_signatures_enabled,   label: 'Signatures Enabled'
        bit1    :encrypt_passwords,             label: 'Encrypted Password', initial_value: 1
        bit1    :user_security,                 label: 'User Level Access',  initial_value: 1
      end
    end
  end
end
