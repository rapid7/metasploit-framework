# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Winpmem

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_WINPMEM = 7000

# Associated command ids
COMMAND_ID_WINPMEM_DUMP_RAM = EXTENSION_ID_WINPMEM + 1

TLV_TYPE_WINPMEM_ERROR_CODE  = TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 1)
TLV_TYPE_WINPMEM_MEMORY_SIZE = TLV_META_TYPE_QWORD | (TLV_EXTENSIONS + 2)

end
end
end
end
end
