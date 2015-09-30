# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Python

TLV_TYPE_PYTHON_STDOUT             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)
TLV_TYPE_PYTHON_STDERR             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
TLV_TYPE_PYTHON_CODE               = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 3)
TLV_TYPE_PYTHON_RESULT_VAR         = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 4)
TLV_TYPE_PYTHON_RESULT             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 5)

end
end
end
end
end
