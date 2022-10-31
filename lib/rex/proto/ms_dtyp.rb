# -*- coding: binary -*-

module Rex::Proto::MsDtyp
  # [2.4.2.2 SID--Packet Representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)
  class MsDtypSid < BinData::Record
    endian :little

    uint8 :revision, initial_value: 1
    uint8 :sub_authority_count, initial_value: -> { sub_authority.length }
    array :identifier_authority, type: :uint8, initial_length: 6
    array :sub_authority, type: :uint32, initial_length: :sub_authority_count
    def assign(val)
      # allow assignment from the human-readable string representation
      if val.is_a?(String) && val =~ /^S-1-(\d+)(-\d+)+$/
        _, _, ia, sa = val.split('-', 4)
        val = {}
        val[:identifier_authority] = [ia.to_i].pack('Q>')[2..].bytes
        val[:sub_authority] = sa.split('-').map(&:to_i)
      end

      super
    end

    def to_s
      str = 'S-1'
      str << "-#{("\x00\x00" + identifier_authority.to_binary_s).unpack1('Q>')}"
      str << '-' + sub_authority.map(&:to_s).join('-')
    end
  end

  # [Universal Unique Identifier](http://pubs.opengroup.org/onlinepubs/9629399/apdxa.htm)
  # The online documentation at [2.3.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40)
  # wierdly doesn't mention this needs to be 4 byte aligned for us to read it correctly,
  # which the RubySMB::Dcerpc::Uuid definition takes care of.
  class MsDtypGuid < RubySMB::Dcerpc::Uuid
  end
end
