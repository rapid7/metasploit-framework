# -*- coding: binary -*-

module Rex::Proto::Thrift
  class ThriftDataType < BinData::Uint8
    T_STOP = 0
    T_UTF7 = 11

    default_parameter assert: -> { !ThriftDataType.name(value).nil? }

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end

  class ThriftMessageType < BinData::Uint16be
    CALL = 1
    REPLY = 2

    default_parameter assert: -> { !MessageType.name(value).nil? }

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end

  class ThriftHeader < BinData::Record
    endian :big
    search_prefix :thrift

    uint16       :version, initial_value: 0x8001
    message_type :message_type
    uint32       :method_name_length, value: -> { method_name.length }
    string       :method_name, read_length: :method_name_length
    uint32       :sequence_id
  end

  class ThriftData < BinData::Record
    endian :big
    search_prefix :thrift

    data_type :data_type, initial_value: ThriftDataType::T_STOP
    uint16    :field_id, onlyif: -> { data_type != ThriftDataType::T_STOP }
    uint32    :data_length, onlyif: -> { data_type != ThriftDataType::T_STOP }, value: -> { data_value.length }
    choice    :data_value, onlyif: -> { data_type != ThriftDataType::T_STOP }, selection: :data_type do
      string ThriftDataType::T_UTF7
    end
  end
end
