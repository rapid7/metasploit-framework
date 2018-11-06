module RubySMB
  module SMB1
    # Represents the Header of an SMB1 packet as defined in
    # [2.2.3.1 SMB Header Extensions](https://msdn.microsoft.com/en-us/library/cc246254.aspx)
    class SMBHeader < BinData::Record
      endian :little
      bit32         :protocol,                    label: 'Protocol ID Field', initial_value: RubySMB::SMB1::SMB_PROTOCOL_ID
      bit8          :command,                     label: 'SMB Command ID'
      nt_status     :nt_status,                   label: 'NTStatus Code'
      header_flags  :flags
      header_flags2 :flags2
      uint16        :pid_high,                    label: 'PID High Bytes'
      string        :security_features,           label: 'Security Features', length: 8
      bit16         :reserved,                    label: 'Reserved'
      bit16         :tid,                         label: 'Tree ID'
      uint16        :pid_low,                     label: 'PID Low Bytes'
      bit16         :uid,                         label: 'User ID'
      uint16        :mid,                         label: 'Multiplex ID'
    end
  end
end
