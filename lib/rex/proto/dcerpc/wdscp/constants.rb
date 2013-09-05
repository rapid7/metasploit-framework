# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
module WDSCP
# http://msdn.microsoft.com/en-us/library/dd891406(prot.20).aspx
# http://msdn.microsoft.com/en-us/library/dd541332(prot.20).aspx
# Not all values defined by the spec have been imported...
class Constants
    WDSCP_RPC_UUID		= "1A927394-352E-4553-AE3F-7CF4AAFCA620"
    OS_DEPLOYMENT_GUID 	= "\x5a\xeb\xde\xd8\xfd\xef\xb2\x43\x99\xfc\x1a\x8a\x59\x21\xc2\x27"

    VAR_NAME_ARCHITECTURE 	= "ARCHITECTURE"
    VAR_NAME_CLIENT_GUID 	= "CLIENT_GUID"
    VAR_NAME_CLIENT_MAC 	= "CLIENT_MAC"
    VAR_NAME_VERSION 	= "VERSION"
    VAR_NAME_MESSAGE_TYPE 	= "MESSAGE_TYPE"
    VAR_NAME_TRANSACTION_ID = "TRANSACTION_ID"
    VAR_NAME_FLAGS		= "FLAGS"
    VAR_NAME_CC		= "CC" #Client Capabilities
    VAR_NAME_IMDC		= "IMDC"

    VAR_TYPE_LOOKUP = {
      VAR_NAME_ARCHITECTURE 	=> :ULONG,
      VAR_NAME_CLIENT_GUID	=> :WSTRING,
      VAR_NAME_CLIENT_MAC	=> :WSTRING,
      VAR_NAME_VERSION	=> :ULONG,
      VAR_NAME_MESSAGE_TYPE	=> :ULONG,
      VAR_NAME_TRANSACTION_ID	=> :WSTRING,
      VAR_NAME_FLAGS		=> :ULONG,
      VAR_NAME_CC		=> :ULONG,
      VAR_NAME_IMDC		=> :ULONG
    }

    CC_FLAGS = {
      :V2	=> 1,
      :VHDX	=> 2
    }

    DOMAIN_JOIN_FLAGS = {
      :JOIN_DOMAIN		=> 1,
      :ACCOUNT_EXISTS		=> 2,
      :PRESTAGE_USING_MAC	=> 3,
      :RESET_BOOT_PROGRAM	=> 256
    }

    ARCHITECTURE = {
      :X64 	=> 9,
      :X86 	=> 0,
      :IA64 	=> 6,
      :ARM 	=> 5
    }

    PACKET_TYPE = {
      :REQUEST 	=> 1,
      :REPLY 		=> 2
    }

    OPCODE = {
      :IMG_ENUMERATE 			=> 2,
      :LOG_INIT 			=> 3,
      :LOG_MSG 			=> 4,
      :GET_CLIENT_UNATTEND 		=> 5,
      :GET_UNATTEND_VARIABLES 	=> 6,
      :GET_DOMAIN_JOIN_INFORMATION 	=> 7,
      :RESET_BOOT_PROGRAM 		=> 8,
      :GET_MACHINE_DRIVER_PACKAGES 	=> 200
    }

    BASE_TYPE = {
      :BYTE		=> 0x0001,
      :USHORT 	=> 0x0002,
      :ULONG	 	=> 0x0004,
      :ULONG64 	=> 0x0008,
      :STRING 	=> 0x0010,
      :WSTRING	=> 0x0020,
      :BLOB	 	=> 0x0040
    }

    TYPE_MODIFIER = {
      :NONE 	=> 0x0000,
      :ARRAY 	=> 0x1000
    }

end
end
end
end
end
