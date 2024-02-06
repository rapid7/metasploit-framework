# -*- coding: binary -*-

require 'bindata'

# @see: https://diwakergupta.github.io/thrift-missing-guide/
module Rex::Proto::Thrift
  class ThriftData < BinData::Record  # forward definition
    endian :big
  end

  class ThriftDataType < BinData::Uint8
    T_STOP = 0
    T_BOOLEAN = 2
    T_I16 = 6
    T_I32 = 8
    T_I64 = 10
    T_UTF7 = 11
    T_STRUCT = 12
    T_SET = 14
    T_LIST = 15

    default_parameter assert: -> { !ThriftDataType.name(value).nil? }

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end

  class ThriftBoolean < BinData::Primitive
    int8 :val

    def get
      self.val != 0
    end

    def set(v)
      self.val = v ? 1 : 0
    end
  end

  class ThriftString < BinData::Primitive
    endian :big

    int32  :len,  value: -> { data.length }
    string :data, read_length: :len

    def get
      self.data.to_s
    end

    def set(v)
      self.data = v
    end
  end

  class ThriftStruct < BinData::Array
    # this is effectively an array terminated by a T_STOP entry
    default_parameter type: :thrift_data
    default_parameter read_until: -> { element.data_type == ThriftDataType::T_STOP }

    # Recursively flatten struct's members into to a hash, keyed by field ID. This is a one way operation because the
    # width of numbers is lost.
    def self.flatten(struct)
      struct = struct.snapshot if struct.is_a?(ThriftStruct)
      flattened = {}
      struct.each do |member|
        case member[:data_type]
        when ThriftDataType::T_STOP
          break
        when ThriftDataType::T_STRUCT
          field_value = flatten(member[:data_value])
        else
          field_value = member[:data_value]
        end

        flattened[member[:field_id]] = field_value
      end

      flattened
    end
  end

  class ThriftArray < BinData::Record
    endian :big

    thrift_data_type :data_type
    int32            :members_size, initial_value: -> { members.num_bytes }
    choice           :members, onlyif: -> { members_size > 0 }, selection: :data_type do
      array ThriftDataType::T_BOOLEAN, type: :thrift_boolean, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_I16, type: :int16, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_I32, type: :int32, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_I64, type: :int64, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_UTF7, type: :thrift_string, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_STRUCT, type: :thrift_struct, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_SET, type: :thrift_array, read_until: -> { members.num_bytes == members_size }
      array ThriftDataType::T_LIST, type: :thrift_array, read_until: -> { members.num_bytes == members_size }
    end
  end

  class ThriftMessageType < BinData::Uint16be
    CALL = 1
    REPLY = 2
    EXCEPTION = 3

    default_parameter assert: -> { !ThriftMessageType.name(value).nil? }

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end

  class ThriftHeader < BinData::Record
    endian :big

    uint16              :version, initial_value: 0x8001
    thrift_message_type :message_type
    thrift_string       :method_name, read_length: :method_name_length
    uint32              :sequence_id
  end

  class ThriftData < BinData::Record
    endian :big

    thrift_data_type :data_type, initial_value: ThriftDataType::T_STOP
    uint16           :field_id, onlyif: -> { data_type != ThriftDataType::T_STOP }
    choice           :data_value, onlyif: -> { data_type != ThriftDataType::T_STOP }, selection: :data_type do
      thrift_boolean  ThriftDataType::T_BOOLEAN
      int16           ThriftDataType::T_I16
      int32           ThriftDataType::T_I32
      int64           ThriftDataType::T_I64
      thrift_string   ThriftDataType::T_UTF7
      thrift_struct   ThriftDataType::T_STRUCT
      thrift_array    ThriftDataType::T_SET
      thrift_array    ThriftDataType::T_LIST
    end

    # Short hand method for defining a boolean field
    def self.boolean(field_id, value)
      { data_type: ThriftDataType::T_BOOLEAN, field_id: field_id, data_value: value }
    end

    def self.i16(field_id, value)
      { data_type: ThriftDataType::T_I16, field_id: field_id, data_value: value }
    end

    def self.i32(field_id, value)
      { data_type: ThriftDataType::T_I32, field_id: field_id, data_value: value }
    end

    def self.i64(field_id, value)
      { data_type: ThriftDataType::T_I64, field_id: field_id, data_value: value }
    end

    def self.list(field_id, data_type, value)
      { data_type: ThriftDataType::T_LIST, field_id: field_id, data_value: { data_type: data_type, members: value } }
    end

    def self.set(field_id, data_type, value)
      { data_type: ThriftDataType::T_SET, field_id: field_id, data_value: { data_type: data_type, members: value } }
    end

    def self.stop
      { data_type: ThriftDataType::T_STOP }
    end

    def self.struct(field_id, value)
      { data_type: ThriftDataType::T_STRUCT, field_id: field_id, data_value: value }
    end

    def self.utf7(field_id, value)
      { data_type: ThriftDataType::T_UTF7, field_id: field_id, data_value: value }
    end
  end

  require 'rex/proto/thrift/client'
  require 'rex/proto/thrift/error'
end
