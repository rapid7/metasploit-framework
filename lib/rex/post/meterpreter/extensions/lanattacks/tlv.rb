# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Lanattacks

TLV_TYPE_LANATTACKS_OPTION      = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 1)
TLV_TYPE_LANATTACKS_OPTION_NAME = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
TLV_TYPE_LANATTACKS_UINT        = TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 3)
TLV_TYPE_LANATTACKS_RAW         = TLV_META_TYPE_RAW    | (TLV_EXTENSIONS + 4)

end
end
end
end
end
