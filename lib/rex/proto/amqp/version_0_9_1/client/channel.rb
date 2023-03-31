class Rex::Proto::Amqp::Version091::Client

  include Rex::Proto::Amqp::Version091

  class Channel
    include Rex::Proto::Amqp::Version091

    # @return [Client] The underlying AMQP client to which this channel belongs.
    attr_reader :client

    # @return [Integer] The channel ID.
    attr_reader :id
    def initialize(client, id)
      @client = client
      @id = id
    end

    # Publish a message on the channel.
    #
    # @param [String] exchange The exchange to publish the message to.
    # @param [String] routing_key The routing key to publish the message with.
    # @param [String] message The message to publish.
    # @param [Hash] properties Properties to include in the content header when publishing.
    # @option properties [String] :content_type
    # @option properties [String] :content_encoding
    # @option properties [AmqpVersion091FieldTable] :headers
    # @option properties [Integer] :delivery_mode
    # @option properties [Integer] :priority
    # @option properties [String] :correlation_id
    # @option properties [String] :reply_to
    # @option properties [String] :expiration
    # @option properties [String] :message_id
    # @option properties [Time] :timestamp
    # @option properties [String] :message_type
    # @option properties [String] :user_id
    # @option properties [String] :app_id
    # @option properties [String] :cluster_id
    # @return [NilClass]
    def basic_publish(exchange: '', routing_key: '', message: '', properties: {})
      ba_publish = Rex::Proto::Amqp::Version091::Frames::AmqpVersion091MethodFrame.new
      ba_publish.header.frame_channel = @id
      ba_publish.arguments = Rex::Proto::Amqp::Version091::Frames::MethodArguments::AmqpVersion091BasicPublish.new
      ba_publish.arguments.exchange = exchange
      ba_publish.arguments.routing_key = routing_key
      @client.send_frame(ba_publish)

      co_header = Rex::Proto::Amqp::Version091::Frames::AmqpVersion091ContentHeaderFrame.new
      co_header.header.frame_channel = @id
      co_header.body_size = message.size
      co_header.flags.snapshot.keys.each do |property|
        next unless properties[property]

        co_header.flags.send(property).assign(true)
        co_header.send(property).assign(properties[property])
      end
      @client.send_frame(co_header)

      co_body = Rex::Proto::Amqp::Version091::Frames::AmqpVersion091ContentBodyFrame.new
      co_body.header.frame_channel = @id
      co_body.payload = message
      @client.send_frame(co_body)

      nil
    end

    def close
      @client.channel_close(self)
    end
  end
end
