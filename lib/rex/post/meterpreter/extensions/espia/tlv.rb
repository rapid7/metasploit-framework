# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Espia

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_ESPIA = 11000

# Associated command ids
COMMAND_ID_ESPIA_IMAGE_GET_DEV_SCREEN = EXTENSION_ID_ESPIA + 1

TLV_TYPE_DEV_IMAGE = TLV_META_TYPE_UINT| (TLV_EXTENSIONS + 911)
TLV_TYPE_DEV_AUDIO = TLV_META_TYPE_STRING| (TLV_EXTENSIONS + 912)
TLV_TYPE_DEV_SCREEN = TLV_META_TYPE_RAW| (TLV_EXTENSIONS + 913)
TLV_TYPE_DEV_RECTIME = TLV_META_TYPE_UINT| (TLV_EXTENSIONS + 914)

end
end
end
end
end
