# -*- coding: binary -*-

require 'bindata'

# types defined in section 4.2 of
# https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
module Rex::Proto::Amqp::Version091::Types
  ##########################################
  # Primitive Scalar Types
  ##########################################
  class AmqpVersion091Boolean < BinData::Primitive
    endian :big

    uint8  :data

    def get
      self.data != 0
    end

    def set(v)
      self.data = v ? 1 : 0
    end
  end

  class AmqpVersion091ShortString < BinData::Primitive
    endian :big

    uint8  :data_length, initial_value: -> { data.length }
    string :data, read_length: :data_length

    def get
      self.data
    end

    def set(v)
      self.data = v
    end
  end

  class AmqpVersion091LongString < BinData::Primitive
    endian  :big

    uint32  :data_length, initial_value: -> { data.length }
    string  :data, read_length: :data_length

    def get
      self.data
    end

    def set(v)
      self.data = v
    end
  end

  class AmqpVersion091Timestamp < BinData::Primitive
    endian :big

    uint64 :data

    def get
      Time.at(self.data)
    end

    def set(v)
      self.data = v.to_i
    end
  end

  ##########################################
  # Compound Forward Declarations
  ##########################################
  class AmqpVersion091FieldTable < BinData::Primitive
    search_prefix   :amqp_version091
  end

  class AmqpVersion091FieldValue < BinData::Record
    search_prefix   :amqp_version091
  end

  class AmqpVersion091FieldValuePair < BinData::Record
    search_prefix   :amqp_version091
  end

  ##########################################
  # Compound Types
  ##########################################
  class AmqpVersion091FieldValueArray < BinData::Array
    endian            :big
    search_prefix     :amqp_version091
    default_parameter type: :field_value
  end

  class AmqpVersion091FieldValuePairArray < BinData::Array
    endian            :big
    search_prefix     :amqp_version091
    default_parameter type: :field_value_pair
  end

  class AmqpVersion091FieldArray < BinData::Primitive
    endian             :big
    search_prefix      :amqp_version091

    uint32             :content_length, initial_value: -> { content.num_bytes }
    field_value_array  :content, read_until: -> { content.num_bytes == content_length }

    def get
      self.content
    end

    def set(v)
      self.content = v
    end

    # Coerce the table into a Ruby array without the AMQP type metadata.
    #
    # @return [Array<Object>]
    def coerce
      content.map do |item|
        case item.data_type
        when 'A'.ord # field-array
          item.data.coerce
        when 'F'.ord # field-table
          item.data.coerce
        else
          item.data.snapshot
        end
      end
    end
  end

  class AmqpVersion091FieldTable < BinData::Primitive
    endian                  :big
    search_prefix           :amqp_version091

    uint32                  :content_length, initial_value: -> { content.num_bytes }
    field_value_pair_array  :content, read_until: -> { content.num_bytes == content_length }

    def get
      self.content
    end

    def set(v)
      self.content = v
    end

    # Coerce the table into a Ruby hash without the AMQP type metadata.
    #
    # @return [Hash<String, Object>]
    def coerce
      content.map do |item|
        case item.data.data_type
        when 'A'.ord # field-array
          [item.name.to_s, item.data.data.coerce]
        when 'F'.ord # field-table
          [item.name.to_s, item.data.data.coerce]
        else
          [item.name.to_s, item.data.data.snapshot]
        end
      end.to_h
    end
  end

  class AmqpVersion091FieldValue < BinData::Record
    endian          :big
    search_prefix   :amqp_version091

    uint8           :data_type
    choice          :data, selection: :data_type do
      boolean       't'.ord                       # boolean
      int8          'b'.ord                       # short-short-int
      uint8         'B'.ord                       # short-short-uint
      int16         'U'.ord                       # short-int
      uint16        'u'.ord                       # short-uint
      int32         'I'.ord                       # long-int
      uint32        'i'.ord                       # long-uint
      int64         'L'.ord                       # long-long-int
      uint64        'l'.ord                       # long-long-uint
      float         'f'.ord                       # float
      double        'd'.ord                       # double
      # decimal     'D'.ord                       # decimal-value
      short_string  's'.ord                       # short-string
      long_string   'S'.ord                       # long-string
      field_array   'A'.ord                       # field-array
      timestamp     'T'.ord                       # timestamp
      field_table   'F'.ord                       # field-table
    end
  end

  class AmqpVersion091FieldValuePair < BinData::Record
    endian          :big
    search_prefix   :amqp_version091

    short_string    :name
    field_value     :data
  end
end

