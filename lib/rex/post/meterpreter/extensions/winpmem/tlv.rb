# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Winpmem
  TLV_TYPE_WINPMEM_ERROR_CODE = TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 1)
  TLV_TYPE_WINPMEM_MEMORY_SIZE = TLV_META_TYPE_QWORD | (TLV_EXTENSIONS + 2)
end
end
end
end
end
