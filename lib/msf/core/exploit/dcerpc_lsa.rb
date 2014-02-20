# -*- coding: binary -*-
module Msf

###
#
# This module provides service-specific methods for the DCERPC exploit mixin
#
###
module Exploit::Remote::DCERPC_LSA

  NDR = Rex::Encoder::NDR

  def lsa_open_policy(dcerpc, server="\\")
    stubdata =
      # Server
      NDR.uwstring(server) +
      # Object Attributes
        NDR.long(24) + # SIZE
        NDR.long(0)  + # LSPTR
        NDR.long(0)  + # NAME
        NDR.long(0)  + # ATTRS
        NDR.long(0)  + # SEC DES
          # LSA QOS PTR
          NDR.long(1)  + # Referent
          NDR.long(12) + # Length
          NDR.long(2)  + # Impersonation
          NDR.long(1)  + # Context Tracking
          NDR.long(0)  + # Effective Only
      # Access Mask
      NDR.long(0x02000000)

    res = dcerpc.call(6, stubdata)

    dcerpc.last_response.stub_data[0,20]
  end

end
end

