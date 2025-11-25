module Rex::Proto::MsTds
  class MsTdsVersion < BinData::Uint32be
    VERSION_7_0 = 0x70
    VERSION_7_1 = 0x71
    VERSION_7_2 = 0x72
    VERSION_7_3 = 0x73
    VERSION_7_4 = 0x74

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end
end
