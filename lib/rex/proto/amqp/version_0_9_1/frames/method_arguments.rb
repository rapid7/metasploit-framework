# -*- coding: binary -*-

require 'bindata'

####################################################
# Method arguments see:
# https://www.rabbitmq.com/amqp-0-9-1-reference.html
####################################################
module Rex::Proto::Amqp::Version091::Frames::MethodArguments

  require 'rex/proto/amqp/version_0_9_1/types'

  class AmqpVersion091BasicPublish < BinData::Record
    CLASS_ID = 60
    METHOD_ID = 40
    endian :big
    search_prefix :amqp_version091

    uint16       :ticket
    short_string :exchange
    short_string :routing_key
    bit6         :reserved_1
    bit1         :immediate
    bit1         :mandatory
  end

  class AmqpVersion091ChannelClose < BinData::Record
    CLASS_ID = 20
    METHOD_ID = 40
    endian :big
    search_prefix :amqp_version091

    uint16       :reply_code, initial_value: 200
    short_string :reply_text, initial_value: 'Normal shutdown'
    uint16       :class_id
    uint16       :method_id
  end

  class AmqpVersion091ChannelCloseOk < BinData::Record
    CLASS_ID = 20
    METHOD_ID = 41
    endian :big
    search_prefix :amqp_version091
  end

  class AmqpVersion091ChannelOpen < BinData::Record
    CLASS_ID = 20
    METHOD_ID = 10
    endian :big
    search_prefix :amqp_version091

    short_string :reserved_1
  end

  class AmqpVersion091ChannelOpenOk < BinData::Record
    CLASS_ID = 20
    METHOD_ID = 11
    endian :big
    search_prefix :amqp_version091

    long_string :reserved_1
  end

  class AmqpVersion091ConnectionClose < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 50
    endian :big
    search_prefix :amqp_version091

    uint16       :reply_code, initial_value: 200
    short_string :reply_text, initial_value: 'Normal shutdown'
    uint16       :class_id
    uint16       :method_id
  end

  class AmqpVersion091ConnectionCloseOk < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 51
    endian :big
    search_prefix :amqp_version091
  end

  class AmqpVersion091ConnectionOpen < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 40
    endian :big
    search_prefix :amqp_version091

    short_string :virtual_host
    short_string :reserved_1
    uint8        :reserved_2
  end

  class AmqpVersion091ConnectionOpenOk < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 41
    endian :big
    search_prefix :amqp_version091

    short_string :reserved_1
  end

  class AmqpVersion091ConnectionStart < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 10
    endian :big
    search_prefix :amqp_version091

    uint8        :version_major
    uint8        :version_minor
    field_table  :server_properties
    long_string  :mechanisms
    long_string  :locales
  end

  class AmqpVersion091ConnectionStartOk < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 11
    endian :big
    search_prefix :amqp_version091

    field_table   :client_properties
    short_string  :mechanism
    long_string   :response
    short_string  :locale
  end

  class AmqpVersion091ConnectionTune < BinData::Record
    CLASS_ID = 10
    METHOD_ID = 30
    endian :big
    search_prefix :amqp_version091

    uint16       :channel_max
    uint32       :frame_max
    uint16       :heartbeat
  end

  class AmqpVersion091ConnectionTuneOk < AmqpVersion091ConnectionTune
    CLASS_ID = 10
    METHOD_ID = 31
  end
end
