# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Powershell

TLV_TYPE_POWERSHELL_SESSIONID        = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)
TLV_TYPE_POWERSHELL_CODE             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
TLV_TYPE_POWERSHELL_RESULT           = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 3)

end
end
end
end
end
