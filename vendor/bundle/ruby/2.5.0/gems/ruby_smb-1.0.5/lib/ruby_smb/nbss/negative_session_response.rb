module RubySMB
  module Nbss


    # Representation of the NetBIOS Negative Session Service Response packet as defined in
    # [4.3.4 SESSION REQUEST PACKET](https://tools.ietf.org/html/rfc1002)
    class NegativeSessionResponse < BinData::Record
      endian :big

      session_header :session_header
      uint8          :error_code, label: 'Error Code'

      def error_msg
        case error_code
        when 0x80
          'Not listening on called name'
        when 0x81
          'Not listening for calling name'
        when 0x82
          'Called name not present'
        when 0x83
          'Called name present, but insufficient resources'
        when 0x8F
          'Unspecified error'
        end
      end
    end

  end
end
