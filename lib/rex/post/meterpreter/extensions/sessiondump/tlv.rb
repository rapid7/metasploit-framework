module Rex
module Post
module Meterpreter
module Extensions
module SessionDump

###
#
# This meterpreter extension can be used to dump hashes and passwords from memory
# Compatible with x86 and x64 systems from Windows XP/2003 to Windows 8/2012
# Author : Steeve Barbeau (steeve DOT barbeau AT hsc DOT fr)
# http://www.hsc.fr/ressources/outils/sessiondump/index.html.en
#
###

# Structure of packets used by the extension

TLV_TYPE_ERROR               = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 1)
# DLL version
TLV_TYPE_VERSION_DLL_REQUEST = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
TLV_TYPE_VERSION_DLL_ANSWER  = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 3)

# Symbols addresses
TLV_TYPE_SYMBOLS_NAME        = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 4)
TLV_TYPE_SYMBOLS_ADDR        = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 5)

# Credentials
TLV_TYPE_DOMAIN              = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 6)
TLV_TYPE_USER                = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 7)
TLV_TYPE_PWD                 = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 8)
TLV_TYPE_LM                  = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9)
TLV_TYPE_NTLM                = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 10)
end
end
end
end
end
