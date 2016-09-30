# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Mimikatz

TLV_TYPE_MIMIKATZ_RESULT	= TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)
TLV_TYPE_MIMIKATZ_FUNCTION	= TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
TLV_TYPE_MIMIKATZ_ARGUMENT	= TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 3)

end
end
end
end
end
