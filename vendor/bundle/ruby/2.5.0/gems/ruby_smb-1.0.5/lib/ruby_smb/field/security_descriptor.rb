module RubySMB
  module Field
    # Class representing a SECURITY_DESCRIPTOR as defined in
    # [2.4.6 SECURITY_DESCRIPTOR](https://msdn.microsoft.com/en-us/library/cc230366.aspx)
    class SecurityDescriptor < BinData::Record
      endian  :little
      uint8   :revision,  label: 'Revision', initial_value: 0x01
      uint8   :sbz1,      label: 'Resource Manager Control Bits'

      struct :control do
        endian  :little
        bit1    :dacl_computed_inheritance, label: 'DACL Computed Inheritance'
        bit1    :sacl_computed_inheritance, label: 'SACL Computed Inheritance'
        bit1    :dacl_auto_inherited,       label: 'DACL Auto-Inherited'
        bit1    :sacl_auto_inherited,       label: 'SACL Auto-Inherited'
        bit1    :dacl_protected,            label: 'DACL Protected'
        bit1    :sacl_protected,            label: 'SACL Protected'
        bit1    :rm_control_valid,          label: 'RM Control Valid'
        bit1    :self_relative,             label: 'Self-Relative Format', initial_value: 0x01
        # Byte Boundary
        bit1    :owner_defaulted,           label: 'Owner Defaulted'
        bit1    :group_defaulted,           label: 'Group Defaulted'
        bit1    :dacl_present,              label: 'DACL Present'
        bit1    :dacl_defaulted,            label: 'DACL Defaulted'
        bit1    :sacl_present,              label: 'SACL Present'
        bit1    :sacl_defaulted,            label: 'SACL Defaulted'
        bit1    :server_security,           label: 'Server Security'
        bit1    :dacl_trusted,              label: 'DACL Trusted'
      end

      uint32  :offset_owner,  label: 'Offset Owner',  initial_value: -> { owner_sid.rel_offset }
      uint32  :offset_group,  label: 'Offset Group',  initial_value: -> { group_sid.rel_offset }
      uint32  :offset_sacl,   label: 'Offset SACL',   initial_value: -> { sacl.rel_offset }
      uint32  :offset_dacl,   label: 'Offset DACL',   initial_value: -> { dacl.rel_offset }

      string  :owner_sid, label: 'Owner SID'
      string  :group_sid, label: 'Group SID'
      string  :sacl,      label: 'SACL'
      string  :dacl,      label: 'DACL'
    end
  end
end
