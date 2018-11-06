module RubySMB
  module SMB1
    module Packet
      module NtTrans
        module Subcommands
          CREATE              = 0x0001
          IOCTL               = 0x0002
          SET_SECURITY_DESC   = 0x0003
          NOTIFY              = 0x0004
          RENAME              = 0x0005
          QUERY_SECURITY_DESC = 0x0006
          GET_USER_QUOTA      = 0x0007
          SET_USER_QUOTA      = 0x0008
        end
      end
    end
  end
end
