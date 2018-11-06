module RubySMB
  module SMB1
    # This module holds the ResourceType used in SMB_COM_OPEN_ANDX and SMB_COM_NT_CREATE_ANDX
    # responses. The definitions for these values can be found at
    # [2.2.4.64.2 Response](https://msdn.microsoft.com/en-us/library/ee441612.aspx)
    # [2.2.4.9.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/cc246334.aspx)
    module ResourceType
      # File or directory
      DISK              = 0x0000
      # Byte mode named pipe
      BYTE_MODE_PIPE    = 0x0001
      # Message mode named pipe
      MESSAGE_MODE_PIPE = 0x0002
      # Printer device
      PRINTER           = 0x0003
    end
  end
end
