module Rex::Proto::MsTds
  class MsTdsStatus < BinData::Uint8
    NORMAL = 0
    END_OF_MESSAGE = 1
    IGNORE_EVENT = 2
    RESETCONNECTION = 8 # TDS 7.1+
    RESECCONNECTIONTRAN = 16 # TDS 7.3+

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end
end
