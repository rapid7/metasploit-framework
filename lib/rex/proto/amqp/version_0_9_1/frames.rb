# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::Amqp::Version091::Frames

  require 'rex/proto/amqp/version_0_9_1/types'
  require 'rex/proto/amqp/version_0_9_1/frames/method_arguments'

  ############################################
  # Frames
  ############################################
  # see: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
  # section 4.2.2
  class AmqpVersion091ProtocolHeader < BinData::Record
    endian :big

    string :protocol, length: 4, initial_value: 'AMQP'.b
    uint8  :protocol_id_major, initial_value: 0
    uint8  :protocol_id_minor, initial_value: 0
    uint8  :version_major, initial_value: 9
    uint8  :version_minor, initial_value: 1
  end

  class AmqpVersion091FrameHeader < BinData::Record
    FRAME_TYPE = 0
    endian :big
    search_prefix  :amqp_version091

    uint8  :frame_type
    uint16 :frame_channel
    uint32 :frame_size, initial_value: -> { parent.num_bytes - (num_bytes + 1) } # +1 for the frame-end field which is not included in the size
  end

  class AmqpVersion091MethodFrame < BinData::Record
    endian :big
    search_prefix :amqp_version091

    frame_header        :header
    uint16              :class_id
    uint16              :method_id
    choice              :arguments, selection: -> { [ class_id, method_id ] } do
      connection_start     [10,10]
      connection_start_ok  [10,11]
      connection_tune      [10,30]
      connection_tune_ok   [10,31]
      connection_open      [10,40]
      connection_open_ok   [10,41]
      connection_close     [10,50]
      connection_close_ok  [10,51]
      channel_open         [20,10]
      channel_open_ok      [20,11]
      channel_close        [20,40]
      channel_close_ok     [20,41]
      basic_publish        [60,40]
    end
    uint8               :frame_end, initial_value: 0xce

    def initialize_shared_instance
      super

      define_singleton_method(:arguments=) do |args|
        if args.class.const_defined?(:CLASS_ID)
          self.class_id = args.class::CLASS_ID
        end
        if args.class.const_defined?(:METHOD_ID)
          self.method_id = args.class::METHOD_ID
        end

        index = @field_names.index(:arguments)
        instantiate_obj_at(index) if @field_objs[index].nil?
        @field_objs[index].assign(args)
      end
    end

    def initialize_instance
      super

      header.frame_type = 1
    end
  end

  class AmqpVersion091ContentHeaderFrame < BinData::Record
    endian :big
    search_prefix :amqp_version091

    frame_header        :header
    uint16              :class_id, initial_value: 60
    uint16              :weight
    uint64              :body_size
    struct              :flags do
      bit1              :content_type
      bit1              :content_encoding
      bit1              :headers
      bit1              :delivery_mode
      bit1              :priority
      bit1              :correlation_id
      bit1              :reply_to
      bit1              :expiration
      bit1              :message_id
      bit1              :timestamp
      bit1              :message_type
      bit1              :user_id
      bit1              :app_id
      bit1              :cluster_id
    end
    short_string        :content_type, onlyif: -> { flags.content_type != 0 }
    short_string        :content_encoding, onlyif: -> { flags.content_encoding != 0 }
    field_table         :headers, onlyif: -> { flags.headers != 0 }
    uint8               :delivery_mode, onlyif: -> { flags.delivery_mode != 0 }
    uint8               :priority, onlyif: -> { flags.priority != 0 }
    short_string        :correlation_id, onlyif: -> { flags.correlation_id != 0 }
    short_string        :reply_to, onlyif: -> { flags.reply_to != 0 }
    short_string        :expiration, onlyif: -> { flags.expiration != 0 }
    short_string        :message_id, onlyif: -> { flags.message_id != 0 }
    timestamp           :timestamp, onlyif: -> { flags.timestamp != 0 }
    short_string        :message_type, onlyif: -> { flags.message_type != 0 }
    short_string        :user_id, onlyif: -> { flags.user_id != 0 }
    short_string        :app_id, onlyif: -> { flags.app_id != 0 }
    short_string        :cluster_id, onlyif: -> { flags.cluster_id != 0 }
    uint8               :frame_end, initial_value: 0xce

    def initialize_instance
      super

      header.frame_type = 2
    end
  end

  class AmqpVersion091ContentBodyFrame < BinData::Record
    endian :big
    search_prefix :amqp_version091

    frame_header        :header
    string              :payload, read_length: -> { header.frame_size }
    uint8               :frame_end, initial_value: 0xce

    def initialize_instance
      super

      header.frame_type = 3
    end
  end
end
