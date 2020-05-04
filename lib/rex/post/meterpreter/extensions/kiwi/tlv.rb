# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Kiwi

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_KIWI = 8000

# Associated command ids
COMMAND_ID_KIWI_EXEC_CMD = EXTENSION_ID_KIWI + 1

TLV_TYPE_KIWI_CMD        = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 100)
TLV_TYPE_KIWI_CMD_RESULT = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 101)

end
end
end
end
end
