module RubySMB
  module Dcerpc
    class PSyntaxIdT < BinData::Record
      endian :little

      uuid   :if_uuid,      initial_value: -> { uuid }
      uint16 :if_ver_major, initial_value: -> { ver_major }
      uint16 :if_ver_minor, initial_value: -> { ver_minor }
    end
  end
end
