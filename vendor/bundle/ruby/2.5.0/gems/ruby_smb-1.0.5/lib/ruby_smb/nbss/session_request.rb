module RubySMB
  module Nbss
    # Representation of the NetBIOS Session Service Request packet as defined in
    # [4.3.2 SESSION REQUEST PACKET](https://tools.ietf.org/html/rfc1002)
    class SessionRequest < BinData::Record
      endian :big

      session_header :session_header
      netbios_name   :called_name,  label: 'Called Name'
      netbios_name   :calling_name, label: 'Calling Name'
    end
  end
end
