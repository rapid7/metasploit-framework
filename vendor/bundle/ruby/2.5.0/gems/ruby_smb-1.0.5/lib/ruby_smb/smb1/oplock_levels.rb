module RubySMB
  module SMB1
    # This module holds the OPLock Levels used in NT_TRANSACT_CREATE and
    # SMB_COM_NT_CREATE_ANDX responses. The definitions for these values can be found at
    # [2.2.7.1.2 Response](https://msdn.microsoft.com/en-us/library/ee441961.aspx)
    module OplockLevels
      # No OpLock Granted
      NO_OPLOCK         = 0x00
      # Exclusive OpLock Granted
      EXCLUSIVE_OPLOCK  = 0x01
      # Batch OpLock Granted
      BATCH_OPLOCK      = 0x02
      # Level 2 OpLock Granted
      LEVEL2_OPLOCK     = 0x03
    end
  end
end
