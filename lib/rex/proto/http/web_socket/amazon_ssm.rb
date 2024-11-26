# -*- coding: binary -*-

require 'bindata'

module Rex::Proto::Http::WebSocket::AmazonSsm
  module PayloadType
    Output               = 1
    Error                = 2
    Size                 = 3
    Parameter            = 4
    HandshakeRequest     = 5
    HandshakeResponse    = 6
    HandshakeComplete    = 7
    EncChallengeRequest  = 8
    EncChallengeResponse = 9
    Flag                 = 10

    def self.from_val(v)
      self.constants.find {|c| self.const_get(c) == v }
    end
  end

  module UUID
    def self.unpack(bbuf)
      sbuf = ""
      [8...12].each do |idx|
        sbuf << Rex::Text.to_hex(bbuf[idx])
      end
      sbuf << '-'
      [12...14].each do |idx|
        sbuf << Rex::Text.to_hex(bbuf[idx])
      end
      sbuf << '-'
      [14...16].each do |idx|
        sbuf << Rex::Text.to_hex(bbuf[idx])
      end
      sbuf << '-'
      [0...2].each do |idx|
        sbuf << Rex::Text.to_hex(bbuf[idx])
      end
      sbuf << '-'
      [2...8].each do |idx|
        sbuf << Rex::Text.to_hex(bbuf[idx])
      end
      sbuf.gsub("\\x",'')
    end

    def self.pack(sbuf)
      parts = sbuf.split('-').map do |seg|
        seg.chars.each_slice(2).map {|e| "\\x#{e.join}"}.join
      end
      [3, 4, 0, 1, 2].map do |part|
        Rex::Text.hex_to_raw(parts[part])
      end.join
    end

    def self.rand
      self.unpack(Rex::Text.rand_text(16))
    end
  end

  module Interface
    module SsmChannelMethods
      attr_accessor :rows
      attr_accessor :cols

      def _start_ssm_keepalive
        @keepalive_thread = Rex::ThreadFactory.spawn('SsmChannel-Keepalive', false) do
          while not closed? or @websocket.closed?
            write ''
            Rex::ThreadSafe.sleep(::Random.rand * 10 + 15)
          end
          @keepalive_thread = nil
        end
      end

      def close
        @keepalive_thread.kill if @keepalive_thread
        @keepalive_thread = nil
        super
      end

      def acknowledge_output(output_frame)
        ack = output_frame.to_ack
        # ack.header.sequence_number = @out_seq_num
        @websocket.put_wsbinary(ack.to_binary_s)
        # wlog("SsmChannel: acknowledge output #{output_frame.uuid}")
        output_frame.uuid
      end

      def pause_publication
        msg = SsmFrame.create_pause_pub
        @publication = false
        @websocket.put_wsbinary(msg.to_binary_s)
      end

      def start_publication
        msg = SsmFrame.create_start_pub
        @publication = true
        @websocket.put_wsbinary(msg.to_binary_s)
      end

      def handle_output_data(output_frame)
        return nil if @ack_message == output_frame.uuid

        @ack_message = acknowledge_output(output_frame)
        # TODO: handle Payload::* types
        if ![PayloadType::Output, PayloadType::Error].any? { |e| e == output_frame.payload_type }
          wlog("SsmChannel got unhandled output payload type: #{Payload.from_val(output_frame.payload_type)}")
          return nil
        end

        output_frame.payload_data.value
      end

      def handle_acknowledge(ack_frame)
        # wlog("SsmChannel: got acknowledge message #{ack_frame.uuid}")
        begin
          seq_num = JSON.parse(ack_frame.payload_data)['AcknowledgedMessageSequenceNumber'].to_i
          @ack_seq_num = seq_num if seq_num > @ack_seq_num
        rescue => e
          elog("SsmChannel failed to parse ack JSON #{ack_frame.payload_data} due to #{e}!")
        end
        nil
      end

      def update_term_size
        return unless ::IO.console

        rows, cols = ::IO.console.winsize
        unless rows == self.rows && cols == self.cols
          set_term_size(cols, rows)
          self.rows = rows
          self.cols = cols
        end
      end

      def set_term_size(cols, rows)
        data = JSON.generate({cols: cols, rows: rows})
        frame = SsmFrame.create(data)
        frame.payload_type = PayloadType::Size
        @websocket.put_wsbinary(frame.to_binary_s)
      end
    end

    class SsmChannel < Rex::Proto::Http::WebSocket::Interface::Channel
      include SsmChannelMethods
      attr_reader :run_ssm_pub, :out_seq_num, :ack_seq_num, :ack_message

      def initialize(websocket)
        @ack_seq_num = 0
        @out_seq_num = 0
        @run_ssm_pub = true
        @ack_message = nil
        @publication = false

        super(websocket, write_type: :binary)
      end

      def on_data_read(data, _data_type)
        return data if data.blank?

        ssm_frame = SsmFrame.read(data)
        case ssm_frame.header.message_type.strip
        when 'output_stream_data'
          @publication = true # Linux sends stream data before sending start_publication message
          return handle_output_data(ssm_frame)
        when 'acknowledge'
          # update ACK seqno
          handle_acknowledge(ssm_frame)
        when 'start_publication'
          @out_seq_num = @ack_seq_num if @out_seq_num > 0
          @publication = true
          # handle session resumption - foregrounding or resumption of input
        when 'pause_publication'
          # @websocket.put_wsbinary(ssm_frame.to_ack.to_binary_s)
          @publication = false
          # handle session suspension - backgrounding or general idle
        when 'input_stream_data'
          # this is supposed to be a one way street
          emsg = "SsmChannel received input_stream_data from SSM (!!)"
          elog(emsg)
          raise emsg
        when 'channel_closed'
          elog("SsmChannel got closed message #{ssm_frame.uuid}")
          close
        else
          raise Rex::Proto::Http::WebSocket::ConnectionError.new(
            msg: "Unknown AWS SSM message type: #{ssm_frame.header.message_type}"
          )
        end

        nil
      end

      def on_data_write(data)
        start_publication if not @publication
        frame = SsmFrame.create(data)
        frame.header.sequence_number = @out_seq_num
        @out_seq_num += 1
        frame.to_binary_s
      end

      def publishing?
        @publication
      end
    end

    def to_ssm_channel(publish_timeout: 10)
      chan = SsmChannel.new(self)

      if publish_timeout
        # Waiting for the channel to start publishing
        (publish_timeout * 2).times do
          break if chan.publishing?

          sleep 0.5
        end

        raise Rex::TimeoutError.new('Timed out while waiting for the channel to start publishing.') unless chan.publishing?
      end

      chan
    end
  end

  class SsmFrame < BinData::Record
    endian :big

    struct :header do
      endian :big

      uint32 :header_length, initial_value: 116
      string :message_type, length: 32, pad_byte: 0x20, initial_value: 'input_stream_data'
      uint32 :schema_version, initial_value: 1
      uint64 :created_date, default_value: lambda { (Time.now.to_f * 1000).to_i }
      uint64 :sequence_number, initial_value: 0
      uint64 :flags, value: 0 #lambda { sequence_number == 0 ? 1 : 0 }
      string :message_id, length: 16, initial_value: UUID.pack(UUID.rand)
    end

    string :payload_digest, length: 32, default_value: -> { Digest::SHA256.digest(payload_data) }
    uint32 :payload_type, default_value: PayloadType::Output
    uint32 :payload_length, value: -> { payload_data.length }
    string :payload_data, read_length: -> { payload_length }

    class << self
      def create(data = nil, mtype = 'input_stream_data')
        return data if data.is_a?(SsmFrame)

        frame = SsmFrame.new(header: {
          message_type: mtype,
          created_date: (Time.now.to_f * 1000).to_i,
          message_id: UUID.pack(UUID.rand)
        })
        if !data.nil?
          frame.payload_data   = data
          frame.payload_digest = Digest::SHA256.digest(data)
          frame.payload_length = data.length
          frame.payload_type   = PayloadType::Output
        end
        frame
      end

      def create_pause_pub
        uuid = UUID.rand
        time = Time.now
        data = JSON.generate({
          MessageType: 'pause_publication',
          SchemaVersion: 1,
          MessageId: uuid,
          CreateData: time.strftime("%Y-%m-%dT%T.%LZ")
        })
        frame = SsmFrame.new( header: {
          message_type: 'pause_publication',
          created_date: (time.to_f * 1000).to_i,
          message_id: UUID.pack(uuid)
        })
        frame.payload_data   = data
        frame.payload_digest = Digest::SHA256.digest(data)
        frame.payload_length = data.length
        frame.payload_type   = 0
        frame
      end

      def create_start_pub
        data = 'start_publication'
        frame = SsmFrame.new( header: {
          message_type: data,
          created_date: (Time.now.to_f * 1000).to_i,
          message_id: UUID.pack(UUID.rand)
        })
        frame.payload_data   = data
        frame.payload_digest = Digest::SHA256.digest(data)
        frame.payload_length = data.length
        frame.payload_type   = 0
        frame
      end

      def from_ws_frame(wsframe)
        SsmFrame.read(wsframe.payload_data)
      end
    end

    def uuid
      UUID.unpack(header.message_id)
    end

    def to_ack
      data = JSON.generate({
        AcknowledgedMessageType: header.message_type.strip,
        AcknowledgedMessageId: uuid,
        AcknowledgedMessageSequenceNumber: header.sequence_number.to_i,
        IsSequentialMessage: true
      })
      ack = SsmFrame.create(data, 'acknowledge')
      ack.header.sequence_number = header.sequence_number
      ack.header.flags = header.flags
      ack
    end

    def length
      to_binary_s.length
    end
  end
  #
  # Initiates a WebSocket session based on the params of SSM::Client#start_session
  #
  # @param [Aws::SSM::Types::StartSessionResponse] :session_init Parameters returned by #start_session
  # @param [Integer] :timeout
  #
  # @return [Socket] Socket representing the authenticates SSM WebSocket connection
  def connect_ssm_ws(session_init, timeout = 20)
    # hack-up a "graceful fail-down" in the caller
    # raise Rex::Proto::Http::WebSocket::ConnectionError.new(msg: 'WebSocket sessions still need structs/parsing')
    ws_key = session_init.token_value
    ssm_id = session_init.session_id
    ws_url = URI.parse(session_init.stream_url)
    opts   = {}
    opts['vhost']   = ws_url.host
    opts['uri']     = ws_url.to_s.sub(/^.*#{ws_url.host}/, '')
    opts['headers'] = {
      'Connection'            => 'Upgrade',
      'Upgrade'               => 'WebSocket',
      'Sec-WebSocket-Version' => 13,
      'Sec-WebSocket-Key'     => ws_key
    }
    ctx = {
      'Msf'        => framework,
      'MsfExploit' => self
    }
    http_client = Rex::Proto::Http::Client.new(ws_url.host, 443, ctx, true)
    raise Rex::Proto::Http::WebSocket::ConnectionError.new if http_client.nil?

    # Send upgrade request
    req = http_client.request_raw(opts)
    res = http_client.send_recv(req, timeout)
    # Verify upgrade
    unless res&.code == 101
      http_client.close
      raise Rex::Proto::Http::WebSocket::ConnectionError.new(http_response: res)
    end
    # see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-WebSocket-Accept
    accept_ws_key = Rex::Text.encode_base64(OpenSSL::Digest::SHA1.digest(ws_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))
    unless res.headers['Sec-WebSocket-Accept'] == accept_ws_key
      http_client.close
      raise Rex::Proto::Http::WebSocket::ConnectionError.new(msg: 'Invalid Sec-WebSocket-Accept header', http_response: res)
    end
    # Extract and extend connection object
    socket = http_client.conn
    socket.extend(Rex::Proto::Http::WebSocket::Interface)
    # Send initialization handshake
    ssm_wsock_init = JSON.generate({
      MessageSchemaVersion: '1.0',
      RequestId: UUID.rand,
      TokenValue: ws_key
    })
    socket.put_wstext(ssm_wsock_init)
    # Extend with interface
    socket.extend(Interface)
  end
end
