module RubySMB
  module SMB2
    module BitField
      # An Access Mask bit field used to describe the permissions on a File, Printer, or named Pipe. As defined in
      # [2.2.13.1.1 File_Pipe_Printer_Access_Mask](https://msdn.microsoft.com/en-us/library/cc246802.aspx)
      class FileAccessMask < BinData::Record
        endian  :little
        bit1    :read_attr,       label: 'Read Attributes'
        bit1    :delete_child,    label: 'Delete Child'
        bit1    :execute,         label: 'Execute'
        bit1    :write_ea,        label: 'Write Extended Attributes'
        bit1    :read_ea,         label: 'Read Extended Attributes'
        bit1    :append_data,     label: 'Append Data'
        bit1    :write_data,      label: 'Write Data'
        bit1    :read_data,       label: 'Read Data'
        # byte boundary
        bit7    :reserved,        label: 'Reserved Space'
        bit1    :write_attr,      label: 'Write Attributes'

        # byte boundary
        bit3    :reserved2,       label: 'Reserved Space'
        bit1    :synchronize,     label: 'Synchronize'
        bit1    :write_owner,     label: 'Write Owner'
        bit1    :write_dac,       label: 'Write DAC'
        bit1    :read_control,    label: 'Read Control'
        bit1    :delete_access,   label: 'Delete'
        # byte boundary
        bit1    :generic_read,    label: 'Generic Read'
        bit1    :generic_write,   label: 'Generic Write'
        bit1    :generic_execute, label: 'Generic Execute'
        bit1    :generic_all,     label: 'Generic All'
        bit2    :reserved3
        bit1    :maximum,         label: 'Maximum Allowed'
        bit1    :system_security, label: 'System Security'
      end
    end
  end
end
