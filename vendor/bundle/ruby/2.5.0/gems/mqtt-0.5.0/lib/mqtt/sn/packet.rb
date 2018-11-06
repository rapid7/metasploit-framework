# encoding: BINARY

module MQTT::SN

  # Class representing a MQTT::SN Packet
  # Performs binary encoding and decoding of headers
  class Packet
    attr_accessor :duplicate     # Duplicate delivery flag
    attr_accessor :qos           # Quality of Service level
    attr_accessor :retain        # Retain flag
    attr_accessor :request_will  # Request that gateway prompts for Will
    attr_accessor :clean_session # When true, subscriptions are deleted after disconnect
    attr_accessor :topic_id_type # One of :normal, :predefined or :short

    DEFAULTS = {}

    # Parse buffer into new packet object
    def self.parse(buffer)
      # Parse the fixed header (length and type)
      length,type_id,body = buffer.unpack('CCa*')
      if length == 1
        length,type_id,body = buffer.unpack('xnCa*')
      end

      # Double-check the length
      if buffer.length != length
        raise ProtocolException.new("Length of packet is not the same as the length header")
      end

      packet_class = PACKET_TYPES[type_id]
      if packet_class.nil?
        raise ProtocolException.new("Invalid packet type identifier: #{type_id}")
      end

      # Create a new packet object
      packet = packet_class.new
      packet.parse_body(body)

      return packet
    end

    # Create a new empty packet
    def initialize(args={})
      update_attributes(self.class::DEFAULTS.merge(args))
    end

    def update_attributes(attr={})
      attr.each_pair do |k,v|
        send("#{k}=", v)
      end
    end

    # Get the identifer for this packet type
    def type_id
      PACKET_TYPES.each_pair do |key, value|
        return key if self.class == value
      end
      raise "Invalid packet type: #{self.class}"
    end

    # Serialise the packet
    def to_s
      # Get the packet's variable header and payload
      body = self.encode_body

      # Build up the body length field bytes
      body_length = body.length
      if body_length > 65531
        raise "MQTT-SN Packet is too big, maximum packet body size is 65531"
      elsif body_length > 253
        [0x01, body_length + 4, type_id].pack('CnC') + body
      else
        [body_length + 2, type_id].pack('CC') + body
      end
    end

    def parse_body(buffer)
    end

    protected

    def parse_flags(flags)
      self.duplicate = ((flags & 0x80) >> 7) == 0x01
      self.qos = (flags & 0x60) >> 5
      self.qos = -1 if self.qos == 3
      self.retain = ((flags & 0x10) >> 4) == 0x01
      self.request_will = ((flags & 0x08) >> 3) == 0x01
      self.clean_session = ((flags & 0x04) >> 2) == 0x01
      case (flags & 0x03)
        when 0x0
          self.topic_id_type = :normal
        when 0x1
          self.topic_id_type = :predefined
        when 0x2
          self.topic_id_type = :short
        else
          self.topic_id_type = nil
      end
    end

    # Get serialisation of packet's body (variable header and payload)
    def encode_body
      '' # No body by default
    end

    def encode_flags
      flags = 0x00
      flags += 0x80 if duplicate
      case qos
        when -1
          flags += 0x60
        when 1
          flags += 0x20
        when 2
          flags += 0x40
      end
      flags += 0x10 if retain
      flags += 0x08 if request_will
      flags += 0x04 if clean_session
      case topic_id_type
        when :normal
          flags += 0x0
        when :predefined
          flags += 0x1
        when :short
          flags += 0x2
      end
      return flags
    end

    def encode_topic_id
      if topic_id_type == :short
        unless topic_id.is_a?(String)
          raise "topic_id must be an String for type #{topic_id_type}"
        end
        (topic_id[0].ord << 8) + topic_id[1].ord
      else
        unless topic_id.is_a?(Integer)
          raise "topic_id must be an Integer for type #{topic_id_type}"
        end
        topic_id
      end
    end

    def parse_topic_id(topic_id)
      if topic_id_type == :short
        int = topic_id.to_i
        self.topic_id = [(int >> 8) & 0xFF, int & 0xFF].pack('CC')
      else
        self.topic_id = topic_id
      end
    end

    # Used where a field can either be a Topic Id or a Topic Name
    # (the Subscribe and Unsubscribe packet types)
    def encode_topic
      case topic_id_type
        when :normal
          topic_name
        when :short
          unless topic_name.nil?
            topic_name
          else
            topic_id
          end
        when :predefined
          [topic_id].pack('n')
      end
    end

    # Used where a field can either be a Topic Id or a Topic Name
    # (the Subscribe and Unsubscribe packet types)
    def parse_topic(topic)
      case topic_id_type
        when :normal
          self.topic_name = topic
        when :short
          self.topic_name = topic
          self.topic_id = topic
        when :predefined
          self.topic_id = topic.unpack('n').first
      end
    end

    class Advertise < Packet
      attr_accessor :gateway_id
      attr_accessor :duration

      DEFAULTS = {
        :gateway_id => 0x00,
        :duration => 0
      }

      def encode_body
        [gateway_id, duration].pack('Cn')
      end

      def parse_body(buffer)
        self.gateway_id, self.duration = buffer.unpack('Cn')
      end
    end

    class Searchgw < Packet
      attr_accessor :radius
      DEFAULTS = {
        :radius => 1
      }

      def encode_body
        [radius].pack('C')
      end

      def parse_body(buffer)
        self.radius, _ignore = buffer.unpack('C')
      end
    end

    class Gwinfo < Packet
      attr_accessor :gateway_id
      attr_accessor :gateway_address
      DEFAULTS = {
        :gateway_id => 0,
        :gateway_address => nil
      }

      def encode_body
        [gateway_id,gateway_address].pack('Ca*')
      end

      def parse_body(buffer)
        if buffer.length > 1
          self.gateway_id, self.gateway_address = buffer.unpack('Ca*')
        else
          self.gateway_id, _ignore = buffer.unpack('C')
          self.gateway_address = nil
        end
      end
    end

    class Connect < Packet
      attr_accessor :keep_alive
      attr_accessor :client_id

      DEFAULTS = {
        :request_will => false,
        :clean_session => true,
        :keep_alive => 15
      }

      # Get serialisation of packet's body
      def encode_body
        if @client_id.nil? or @client_id.length < 1 or @client_id.length > 23
          raise "Invalid client identifier when serialising packet"
        end

        [encode_flags, 0x01, keep_alive, client_id].pack('CCna*')
      end

      def parse_body(buffer)
        flags, protocol_id, self.keep_alive, self.client_id = buffer.unpack('CCna*')

        if protocol_id != 0x01
          raise ProtocolException.new("Unsupported protocol ID number: #{protocol_id}")
        end

        parse_flags(flags)
      end
    end

    class Connack < Packet
      attr_accessor :return_code

      # Get a string message corresponding to a return code
      def return_msg
        case return_code
          when 0x00
            "Accepted"
          when 0x01
            "Rejected: congestion"
          when 0x02
            "Rejected: invalid topic ID"
          when 0x03
            "Rejected: not supported"
          else
            "Rejected: error code #{return_code}"
        end
      end

      def encode_body
        unless return_code.is_a?(Integer)
          raise "return_code must be an Integer"
        end

        [return_code].pack('C')
      end

      def parse_body(buffer)
        self.return_code = buffer.unpack('C')[0]
      end
    end

    class Willtopicreq < Packet
      # No attributes
    end

    class Willtopic < Packet
      attr_accessor :topic_name

      DEFAULTS = {
        :qos => 0,
        :retain => false,
        :topic_name => nil
      }

      def encode_body
        if topic_name.nil? or topic_name.empty?
          ''
        else
          [encode_flags, topic_name].pack('Ca*')
        end
      end

      def parse_body(buffer)
        if buffer.length > 1
          flags, self.topic_name = buffer.unpack('Ca*')
        else
          flags, _ignore = buffer.unpack('C')
          self.topic_name = nil
        end
        parse_flags(flags)
      end
    end

    class Willmsgreq < Packet
      # No attributes
    end

    class Willmsg < Packet
      attr_accessor :data

      def encode_body
        data
      end

      def parse_body(buffer)
        self.data = buffer
      end
    end

    class Register < Packet
      attr_accessor :id
      attr_accessor :topic_id
      attr_accessor :topic_name

      DEFAULTS = {
        :id => 0x00,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        unless topic_id.is_a?(Integer)
          raise "topic_id must be an Integer"
        end

        [topic_id, id, topic_name].pack('nna*')
      end

      def parse_body(buffer)
        self.topic_id, self.id, self.topic_name = buffer.unpack('nna*')
      end
    end

    class Regack < Packet
      attr_accessor :id
      attr_accessor :topic_id
      attr_accessor :return_code

      DEFAULTS = {
        :id => 0x00,
        :topic_id => 0x00,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        unless topic_id.is_a?(Integer)
          raise "topic_id must be an Integer"
        end

        [topic_id, id, return_code].pack('nnC')
      end

      def parse_body(buffer)
        self.topic_id, self.id, self.return_code = buffer.unpack('nnC')
      end
    end

    class Publish < Packet
      attr_accessor :topic_id
      attr_accessor :id
      attr_accessor :data

      DEFAULTS = {
        :id => 0x00,
        :duplicate => false,
        :qos => 0,
        :retain => false,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [encode_flags, encode_topic_id, id, data].pack('Cnna*')
      end

      def parse_body(buffer)
        flags, topic_id, self.id, self.data = buffer.unpack('Cnna*')
        parse_flags(flags)
        parse_topic_id(topic_id)
      end
    end

    class Puback < Packet
      attr_accessor :topic_id
      attr_accessor :id
      attr_accessor :return_code

      DEFAULTS = {
        :id => 0x00,
        :topic_id => nil,
        :return_code => 0x00,
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        unless topic_id.is_a?(Integer)
          raise "topic_id must be an Integer"
        end

        [topic_id, id, return_code].pack('nnC')
      end

      def parse_body(buffer)
        self.topic_id, self.id, self.return_code = buffer.unpack('nnC')
      end
    end

    class Pubcomp < Packet
      attr_accessor :id

      DEFAULTS = {
        :id => 0x00
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [id].pack('n')
      end

      def parse_body(buffer)
        self.id, _ignore = buffer.unpack('n')
      end
    end

    class Pubrec < Packet
      attr_accessor :id

      DEFAULTS = {
        :id => 0x00
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [id].pack('n')
      end

      def parse_body(buffer)
        self.id, _ignore = buffer.unpack('n')
      end
    end

    class Pubrel < Packet
      attr_accessor :id

      DEFAULTS = {
        :id => 0x00
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [id].pack('n')
      end

      def parse_body(buffer)
        self.id, _ignore = buffer.unpack('n')
      end
    end

    class Subscribe < Packet
      attr_accessor :id
      attr_accessor :topic_id
      attr_accessor :topic_name

      DEFAULTS = {
        :id => 0x00,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [encode_flags, id, encode_topic].pack('Cna*')
      end

      def parse_body(buffer)
        flags, self.id, topic = buffer.unpack('Cna*')
        parse_flags(flags)
        parse_topic(topic)
      end
    end

    class Suback < Packet
      attr_accessor :id
      attr_accessor :topic_id
      attr_accessor :return_code

      DEFAULTS = {
        :qos => 0,
        :id => 0x00,
        :topic_id => 0x00,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [encode_flags, encode_topic_id, id, return_code].pack('CnnC')
      end

      def parse_body(buffer)
        flags, topic_id, self.id, self.return_code = buffer.unpack('CnnC')
        parse_flags(flags)
        parse_topic_id(topic_id)
      end
    end

    class Unsubscribe < Packet
      attr_accessor :id
      attr_accessor :topic_id
      attr_accessor :topic_name

      DEFAULTS = {
        :id => 0x00,
        :topic_id_type => :normal
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [encode_flags, id, encode_topic].pack('Cna*')
      end

      def parse_body(buffer)
        flags, self.id, topic = buffer.unpack('Cna*')
        parse_flags(flags)
        parse_topic(topic)
      end
    end

    class Unsuback < Packet
      attr_accessor :id

      DEFAULTS = {
        :id => 0x00,
      }

      def encode_body
        unless id.is_a?(Integer)
          raise "id must be an Integer"
        end

        [id].pack('n')
      end

      def parse_body(buffer)
        self.id = buffer.unpack('n').first
      end
    end

    class Pingreq < Packet
      # No attributes
    end

    class Pingresp < Packet
      # No attributes
    end

    class Disconnect < Packet
      attr_accessor :duration

      DEFAULTS = {
        :duration => nil
      }

      def encode_body
        if duration.nil? or duration == 0
          ''
        else
          [duration].pack('n')
        end
      end

      def parse_body(buffer)
        if buffer.length == 2
          self.duration = buffer.unpack('n').first
        else
          self.duration = nil
        end
      end
    end

    class Willtopicupd < Packet
      attr_accessor :topic_name

      DEFAULTS = {
        :qos => 0,
        :retain => false,
        :topic_name => nil
      }

      def encode_body
        if topic_name.nil? or topic_name.empty?
          ''
        else
          [encode_flags, topic_name].pack('Ca*')
        end
      end

      def parse_body(buffer)
        if buffer.length > 1
          flags, self.topic_name = buffer.unpack('Ca*')
          parse_flags(flags)
        else
          self.topic_name = nil
        end
      end
    end

    class Willtopicresp < Packet
      attr_accessor :return_code

      DEFAULTS = {
        :return_code => 0x00
      }

      def encode_body
        unless return_code.is_a?(Integer)
          raise "return_code must be an Integer"
        end

        [return_code].pack('C')
      end

      def parse_body(buffer)
        self.return_code, _ignore = buffer.unpack('C')
      end
    end

    class Willmsgupd < Packet
      attr_accessor :data

      def encode_body
        data
      end

      def parse_body(buffer)
        self.data = buffer
      end
    end

    class Willmsgresp < Packet
      attr_accessor :return_code

      DEFAULTS = {
        :return_code => 0x00
      }

      def encode_body
        unless return_code.is_a?(Integer)
          raise "return_code must be an Integer"
        end

        [return_code].pack('C')
      end

      def parse_body(buffer)
        self.return_code, _ignore = buffer.unpack('C')
      end
    end

  end


  # An enumeration of the MQTT-SN packet types
  PACKET_TYPES = {
      0x00 => MQTT::SN::Packet::Advertise,
      0x01 => MQTT::SN::Packet::Searchgw,
      0x02 => MQTT::SN::Packet::Gwinfo,
      0x04 => MQTT::SN::Packet::Connect,
      0x05 => MQTT::SN::Packet::Connack,
      0x06 => MQTT::SN::Packet::Willtopicreq,
      0x07 => MQTT::SN::Packet::Willtopic,
      0x08 => MQTT::SN::Packet::Willmsgreq,
      0x09 => MQTT::SN::Packet::Willmsg,
      0x0a => MQTT::SN::Packet::Register,
      0x0b => MQTT::SN::Packet::Regack,
      0x0c => MQTT::SN::Packet::Publish,
      0x0d => MQTT::SN::Packet::Puback,
      0x0e => MQTT::SN::Packet::Pubcomp,
      0x0f => MQTT::SN::Packet::Pubrec,
      0x10 => MQTT::SN::Packet::Pubrel,
      0x12 => MQTT::SN::Packet::Subscribe,
      0x13 => MQTT::SN::Packet::Suback,
      0x14 => MQTT::SN::Packet::Unsubscribe,
      0x15 => MQTT::SN::Packet::Unsuback,
      0x16 => MQTT::SN::Packet::Pingreq,
      0x17 => MQTT::SN::Packet::Pingresp,
      0x18 => MQTT::SN::Packet::Disconnect,
      0x1a => MQTT::SN::Packet::Willtopicupd,
      0x1b => MQTT::SN::Packet::Willtopicresp,
      0x1c => MQTT::SN::Packet::Willmsgupd,
      0x1d => MQTT::SN::Packet::Willmsgresp,
  }

end
