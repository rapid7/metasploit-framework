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

      def strip_ctl_bytes(tty_out)
        tty_out.gsub(/\e\[(?:[0-9];?)+m/, '').gsub(/^\e.+;/,'')
      end

      def handle_output_data(output_frame)
        if @ack_message == output_frame.uuid
          # wlog("SsmChannel: repeat output #{output_frame.uuid}")
        else
          @ack_message = acknowledge_output(output_frame)
          # TODO: handle Payload::* types
          if [PayloadType::Output, PayloadType::Error].any? { |e| e == output_frame.payload_type }
            if @filter_echo.is_a?(String) and output_frame.payload_data.strip == @filter_echo.strip
              dlog("SsmChannel: filtering output #{@filter_echo}")
              @filter_echo = true
              return nil
            else
              return @filter_text ? strip_ctl_bytes(output_frame.payload_data) : output_frame.payload_data
            end
          else
            wlog("SsmChannel got unhandled output payload type: #{Payload.from_val(output_frame.payload_type)}")
          end
        end
        nil
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
          set_term_size(rows, cols)
          self.rows = rows
          self.cols = cols
        end
      end

      def set_term_size(cols, rows)
        data = JSON.generate({cols: cols, rows: rows})
        frame = SsmFrame.create(data)
        frame.payload_type = PayloadType::Size
        write(frame)
      end
    end

    class SsmChannel < Rex::Proto::Http::WebSocket::Interface::Channel
      include SsmChannelMethods
      attr_reader :run_ssm_pub, :out_seq_num, :ack_seq_num, :ack_message
      attr_accessor :filter_echo

      def initialize(websocket, filter_echo = false, filter_text = true)
        @ack_seq_num = 0
        @out_seq_num = 0
        @run_ssm_pub = true
        @ack_message = nil
        @filter_echo = filter_echo
        @filter_text = filter_text

        super(websocket, write_type: :binary)
      end

      def on_data_read(data, _data_type)
        return data if data.blank?

        ssm_frame = SsmFrame.read(data)
        case ssm_frame.header.message_type.strip
        when 'output_stream_data'
          return handle_output_data(ssm_frame)
        when 'acknowledge'
          # update ACK seqno
          handle_acknowledge(ssm_frame)
        when 'start_publication'
          # handle session resumption - foregrounding or resumption of input
        when 'pause_publication'
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
        @filter_echo = data if @filter_echo and data.is_a?(String)
        frame = SsmFrame.create(data)
        frame.header.sequence_number = @out_seq_num
        @out_seq_num += 1
        frame.to_binary_s
      end
    end

    def to_ssm_channel(filter_echo = true)
      SsmChannel.new(self, filter_echo)
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

    string :payload_digest, length: 32, default_value: lambda { Digest::SHA256.digest(payload_data) }
    uint32 :payload_type, default_value: PayloadType::Output
    uint32 :payload_length, value: lambda { payload_data.length }
    string :payload_data, read_length: -> { payload_length }

    class << self
      def create(data = nil, mtype = 'input_stream_data')
        return data if data.is_a?(SsmFrame)
        frame = SsmFrame.new( header: {
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

      def from_ws_frame(wsframe)
        SsmFrame.read(wsframe.payload_data)
      end
    end

    def uuid
      UUID.unpack(header.message_id)
    end

    def to_ack
      data   = JSON.generate({
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
