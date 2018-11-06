require 'net/ssh/buffered_io'
require 'net/ssh/errors'
require 'net/ssh/packet'
require 'net/ssh/ruby_compat'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/hmac'
require 'net/ssh/transport/state'

module Net
  module SSH
    module Transport

      # A module that builds additional functionality onto the Net::SSH::BufferedIo
      # module. It adds SSH encryption, compression, and packet validation, as
      # per the SSH2 protocol. It also adds an abstraction for polling packets,
      # to allow for both blocking and non-blocking reads.
      module PacketStream
        PROXY_COMMAND_HOST_IP = '<no hostip for proxy command>'.freeze

        include BufferedIo

        def self.extended(object)
          object.__send__(:initialize_ssh)
        end

        # The map of "hints" that can be used to modify the behavior of the packet
        # stream. For instance, when authentication succeeds, an "authenticated"
        # hint is set, which is used to determine whether or not to compress the
        # data when using the "delayed" compression algorithm.
        attr_reader :hints

        # The server state object, which encapsulates the algorithms used to interpret
        # packets coming from the server.
        attr_reader :server

        # The client state object, which encapsulates the algorithms used to build
        # packets to send to the server.
        attr_reader :client

        # The name of the client (local) end of the socket, as reported by the
        # socket.
        def client_name
          @client_name ||= begin
            sockaddr = getsockname
            begin
              Socket.getnameinfo(sockaddr, Socket::NI_NAMEREQD).first
            rescue StandardError
              begin
                Socket.getnameinfo(sockaddr).first
              rescue StandardError
                begin
                  Socket.gethostbyname(Socket.gethostname).first
                rescue StandardError
                  lwarn { "the client ipaddr/name could not be determined" }
                  "unknown"
                end
              end
            end
          end
        end

        # The IP address of the peer (remote) end of the socket, as reported by
        # the socket.
        def peer_ip
          @peer_ip ||=
            if respond_to?(:getpeername)
              addr = getpeername
              Socket.getnameinfo(addr, Socket::NI_NUMERICHOST | Socket::NI_NUMERICSERV).first
            else
              PROXY_COMMAND_HOST_IP
            end
        end

        # Returns true if the IO is available for reading, and false otherwise.
        def available_for_read?
          result = IO.select([self], nil, nil, 0)
          result && result.first.any?
        end

        # Returns the next full packet. If the mode parameter is :nonblock (the
        # default), then this will return immediately, whether a packet is
        # available or not, and will return nil if there is no packet ready to be
        # returned. If the mode parameter is :block, then this method will block
        # until a packet is available.
        def next_packet(mode=:nonblock)
          case mode
          when :nonblock then
            packet = poll_next_packet
            return packet if packet

            if available_for_read?
              if fill <= 0
                result = poll_next_packet
                if result.nil?
                  raise Net::SSH::Disconnect, "connection closed by remote host"
                else
                  return result
                end
              end
            end
            poll_next_packet

          when :block then
            loop do
              packet = poll_next_packet
              return packet if packet

              loop do
                result = IO.select([self]) or next
                break if result.first.any?
              end

              raise Net::SSH::Disconnect, "connection closed by remote host" if fill <= 0
            end

          else
            raise ArgumentError, "expected :block or :nonblock, got #{mode.inspect}"
          end
        end

        # Enqueues a packet to be sent, and blocks until the entire packet is
        # sent.
        def send_packet(payload)
          enqueue_packet(payload)
          wait_for_pending_sends
        end

        # Enqueues a packet to be sent, but does not immediately send the packet.
        # The given payload is pre-processed according to the algorithms specified
        # in the client state (compression, cipher, and hmac).
        def enqueue_packet(payload)
          # try to compress the packet
          payload = client.compress(payload)

          # the length of the packet, minus the padding
          actual_length = 4 + payload.bytesize + 1

          # compute the padding length
          padding_length = client.block_size - (actual_length % client.block_size)
          padding_length += client.block_size if padding_length < 4

          # compute the packet length (sans the length field itself)
          packet_length = payload.bytesize + padding_length + 1

          if packet_length < 16
            padding_length += client.block_size
            packet_length = payload.bytesize + padding_length + 1
          end

          padding = Array.new(padding_length) { rand(256) }.pack("C*")

          unencrypted_data = [packet_length, padding_length, payload, padding].pack("NCA*A*")
          mac = client.hmac.digest([client.sequence_number, unencrypted_data].pack("NA*"))

          encrypted_data = client.update_cipher(unencrypted_data) << client.final_cipher
          message = encrypted_data + mac

          debug { "queueing packet nr #{client.sequence_number} type #{payload.getbyte(0)} len #{packet_length}" }
          enqueue(message)

          client.increment(packet_length)

          self
        end

        # Performs any pending cleanup necessary on the IO and its associated
        # state objects. (See State#cleanup).
        def cleanup
          client.cleanup
          server.cleanup
        end

        # If the IO object requires a rekey operation (as indicated by either its
        # client or server state objects, see State#needs_rekey?), this will
        # yield. Otherwise, this does nothing.
        def if_needs_rekey?
          if client.needs_rekey? || server.needs_rekey?
            yield
            client.reset! if client.needs_rekey?
            server.reset! if server.needs_rekey?
          end
        end

        protected

        # Called when this module is used to extend an object. It initializes
        # the states and generally prepares the object for use as a packet stream.
        def initialize_ssh
          @hints  = {}
          @server = State.new(self, :server)
          @client = State.new(self, :client)
          @packet = nil
          initialize_buffered_io
        end

        # Tries to read the next packet. If there is insufficient data to read
        # an entire packet, this returns immediately, otherwise the packet is
        # read, post-processed according to the cipher, hmac, and compression
        # algorithms specified in the server state object, and returned as a
        # new Packet object.
        def poll_next_packet
          if @packet.nil?
            minimum = server.block_size < 4 ? 4 : server.block_size
            return nil if available < minimum
            data = read_available(minimum)

            # decipher it
            @packet = Net::SSH::Buffer.new(server.update_cipher(data))
            @packet_length = @packet.read_long
          end

          need = @packet_length + 4 - server.block_size
          raise Net::SSH::Exception, "padding error, need #{need} block #{server.block_size}" if need % server.block_size != 0

          return nil if available < need + server.hmac.mac_length

          if need > 0
            # read the remainder of the packet and decrypt it.
            data = read_available(need)
            @packet.append(server.update_cipher(data))
          end

          # get the hmac from the tail of the packet (if one exists), and
          # then validate it.
          real_hmac = read_available(server.hmac.mac_length) || ""

          @packet.append(server.final_cipher)
          padding_length = @packet.read_byte

          payload = @packet.read(@packet_length - padding_length - 1)

          my_computed_hmac = server.hmac.digest([server.sequence_number, @packet.content].pack("NA*"))
          raise Net::SSH::Exception, "corrupted hmac detected" if real_hmac != my_computed_hmac

          # try to decompress the payload, in case compression is active
          payload = server.decompress(payload)

          debug { "received packet nr #{server.sequence_number} type #{payload.getbyte(0)} len #{@packet_length}" }

          server.increment(@packet_length)
          @packet = nil

          return Packet.new(payload)
        end
      end

    end
  end
end
