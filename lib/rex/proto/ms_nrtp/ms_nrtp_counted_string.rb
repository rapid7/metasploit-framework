module Rex::Proto::MsNrtp
  class MsNrtpCountedString < BinData::Primitive
    # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/fea06769-1899-422e-9230-ce3a58710c20
    endian :little

    uint8       :string_encoding
    uint32      :string_length, initial_value: -> { string_data.length }
    uint8_array :string_data, initial_length: :string_length

    def get
      self.string_data.to_binary_s.force_encoding(self.string_encoding == 0 ? Encoding::UTF_16LE : Encoding::UTF_8)
    end

    def set(v)
      self.string_data = v.bytes
      if v.encoding == Encoding::UTF_16LE
        self.string_encoding = 0
      elsif v.encoding == Encoding::UTF_8
        self.string_encoding = 1
      else
        raise ::EncodingError, 'strings must be UTF-8 or UTF-16'
      end
    end
  end
end
