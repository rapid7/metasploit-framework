# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Unhook

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_UNHOOK = 10000

# Associated command ids
COMMAND_ID_UNHOOK_PE = EXTENSION_ID_UNHOOK + 1

TLV_TYPE_UNHOOK_ERROR_CODE = TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 1)

end
end
end
end
end
