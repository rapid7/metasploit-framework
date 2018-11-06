require 'zlib'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/hmac'

module Net 
  module SSH 
    module Transport

      # Encapsulates state information about one end of an SSH connection. Such
      # state includes the packet sequence number, the algorithms in use, how
      # many packets and blocks have been processed since the last reset, and so
      # forth. This class will never be instantiated directly, but is used as
      # part of the internal state of the PacketStream module.
      class State
        # The socket object that owns this state object.
        attr_reader :socket
    
        # The next packet sequence number for this socket endpoint.
        attr_reader :sequence_number
    
        # The hmac algorithm in use for this endpoint.
        attr_reader :hmac
    
        # The compression algorithm in use for this endpoint.
        attr_reader :compression
    
        # The compression level to use when compressing data (or nil, for the default).
        attr_reader :compression_level
    
        # The number of packets processed since the last call to #reset!
        attr_reader :packets
    
        # The number of data blocks processed since the last call to #reset!
        attr_reader :blocks
    
        # The cipher algorithm in use for this socket endpoint.
        attr_reader :cipher
    
        # The block size for the cipher
        attr_reader :block_size
    
        # The role that this state plays (either :client or :server)
        attr_reader :role
    
        # The maximum number of packets that this endpoint wants to process before
        # needing a rekey.
        attr_accessor :max_packets
    
        # The maximum number of blocks that this endpoint wants to process before
        # needing a rekey.
        attr_accessor :max_blocks
    
        # The user-specified maximum number of bytes that this endpoint ought to
        # process before needing a rekey.
        attr_accessor :rekey_limit
    
        # Creates a new state object, belonging to the given socket. Initializes
        # the algorithms to "none".
        def initialize(socket, role)
          @socket = socket
          @role = role
          @sequence_number = @packets = @blocks = 0
          @cipher = CipherFactory.get("none")
          @block_size = 8
          @hmac = HMAC.get("none")
          @compression = nil
          @compressor = @decompressor = nil
          @next_iv = ""
        end
    
        # A convenience method for quickly setting multiple values in a single
        # command.
        def set(values)
          values.each do |key, value|
            instance_variable_set("@#{key}", value)
          end
          reset!
        end
    
        def update_cipher(data)
          result = cipher.update(data)
          update_next_iv(role == :client ? result : data)
          return result
        end
    
        def final_cipher
          result = cipher.final
          update_next_iv(role == :client ? result : "", true)
          return result
        end
    
        # Increments the counters. The sequence number is incremented (and remapped
        # so it always fits in a 32-bit integer). The number of packets and blocks
        # are also incremented.
        def increment(packet_length)
          @sequence_number = (@sequence_number + 1) & 0xFFFFFFFF
          @packets += 1
          @blocks += (packet_length + 4) / @block_size
        end
    
        # The compressor object to use when compressing data. This takes into account
        # the desired compression level.
        def compressor
          @compressor ||= Zlib::Deflate.new(compression_level || Zlib::DEFAULT_COMPRESSION)
        end
    
        # The decompressor object to use when decompressing data.
        def decompressor
          @decompressor ||= Zlib::Inflate.new(nil)
        end
    
        # Returns true if data compression/decompression is enabled. This will
        # return true if :standard compression is selected, or if :delayed
        # compression is selected and the :authenticated hint has been received
        # by the socket.
        def compression?
          compression == :standard || (compression == :delayed && socket.hints[:authenticated])
        end
    
        # Compresses the data. If no compression is in effect, this will just return
        # the data unmodified, otherwise it uses #compressor to compress the data.
        def compress(data)
          data = data.to_s
          return data unless compression?
          compressor.deflate(data, Zlib::SYNC_FLUSH)
        end
    
        # Deompresses the data. If no compression is in effect, this will just return
        # the data unmodified, otherwise it uses #decompressor to decompress the data.
        def decompress(data)
          data = data.to_s
          return data unless compression?
          decompressor.inflate(data)
        end
    
        # Resets the counters on the state object, but leaves the sequence_number
        # unchanged. It also sets defaults for and recomputes the max_packets and
        # max_blocks values.
        def reset!
          @packets = @blocks = 0
    
          @max_packets ||= 1 << 31
    
          @block_size = cipher.name == "RC4" ? 8 : cipher.block_size
    
          if max_blocks.nil?
            # cargo-culted from openssh. the idea is that "the 2^(blocksize*2)
            # limit is too expensive for 3DES, blowfish, etc., so enforce a 1GB
            # limit for small blocksizes."
            if @block_size >= 16
              @max_blocks = 1 << (@block_size * 2)
            else
              @max_blocks = (1 << 30) / @block_size
            end
    
            # if a limit on the # of bytes has been given, convert that into a
            # minimum number of blocks processed.
    
            @max_blocks = [@max_blocks, rekey_limit / @block_size].min if rekey_limit
          end
    
          cleanup
        end
    
        # Closes any the compressor and/or decompressor objects that have been
        # instantiated.
        def cleanup
          if @compressor
            @compressor.finish if !@compressor.finished?
            @compressor.close
          end
    
          if @decompressor
            # we call reset here so that we don't get warnings when we try to
            # close the decompressor
            @decompressor.reset
            @decompressor.close
          end
    
          @compressor = @decompressor = nil
        end
    
        # Returns true if the number of packets processed exceeds the maximum
        # number of packets, or if the number of blocks processed exceeds the
        # maximum number of blocks.
        def needs_rekey?
          max_packets && packets > max_packets ||
          max_blocks && blocks > max_blocks
        end
    
        private
    
        def update_next_iv(data, reset=false)
          @next_iv << data
          @next_iv = @next_iv[@next_iv.size - cipher.iv_len..-1]
    
          if reset
            cipher.reset
            cipher.iv = @next_iv
          end
    
          return data
        end
      end

    end
  end
end
