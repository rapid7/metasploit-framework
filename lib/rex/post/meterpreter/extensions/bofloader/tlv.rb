# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Bofloader

TLV_TYPE_BOFLOADER_CMD        = TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 100)
TLV_TYPE_BOFLOADER_CMD_RESULT = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 101)

end
end
end
end
end
