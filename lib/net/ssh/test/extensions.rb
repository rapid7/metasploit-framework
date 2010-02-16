require 'net/ssh/buffer'
require 'net/ssh/packet'
require 'net/ssh/buffered_io'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/constants'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/packet_stream'

module Net; module SSH; module Test

  # A collection of modules used to extend/override the default behavior of
  # Net::SSH internals for ease of testing. As a consumer of Net::SSH, you'll
  # never need to use this directly--they're all used under the covers by
  # the Net::SSH::Test system.
  module Extensions

    # An extension to Net::SSH::BufferedIo (assumes that the underlying IO
    # is actually a StringIO). Facilitates unit testing.
    module BufferedIo
      # Returns +true+ if the position in the stream is less than the total
      # length of the stream.
      def select_for_read?
        pos < size
      end

      # Set this to +true+ if you want the IO to pretend to be available for writing
      attr_accessor :select_for_write

      # Set this to +true+ if you want the IO to pretend to be in an error state
      attr_accessor :select_for_error

      alias select_for_write? select_for_write
      alias select_for_error? select_for_error
    end

    # An extension to Net::SSH::Transport::PacketStream (assumes that the
    # underlying IO is actually a StringIO). Facilitates unit testing.
    module PacketStream
      include BufferedIo # make sure we get the extensions here, too

      def self.included(base) #:nodoc:
        base.send :alias_method, :real_available_for_read?, :available_for_read?
        base.send :alias_method, :available_for_read?, :test_available_for_read?

        base.send :alias_method, :real_enqueue_packet, :enqueue_packet
        base.send :alias_method, :enqueue_packet, :test_enqueue_packet

        base.send :alias_method, :real_poll_next_packet, :poll_next_packet
        base.send :alias_method, :poll_next_packet, :test_poll_next_packet
      end

      # Called when another packet should be inspected from the current
      # script. If the next packet is a remote packet, it pops it off the
      # script and shoves it onto this IO object, making it available to
      # be read.
      def idle!
        return false unless script.next(:first)

        if script.next(:first).remote?
          self.string << script.next.to_s
          self.pos = pos
        end

        return true
      end

      # The testing version of Net::SSH::Transport::PacketStream#available_for_read?.
      # Returns true if there is data pending to be read. Otherwise calls #idle!.
      def test_available_for_read?
        return true if select_for_read?
        idle!
        false
      end

      # The testing version of Net::SSH::Transport::PacketStream#enqueued_packet.
      # Simply calls Net::SSH::Test::Script#process on the packet.
      def test_enqueue_packet(payload)
        packet = Net::SSH::Buffer.new(payload.to_s)
        script.process(packet)
      end

      # The testing version of Net::SSH::Transport::PacketStream#poll_next_packet.
      # Reads the next available packet from the IO object and returns it.
      def test_poll_next_packet
        return nil if available <= 0
        packet = Net::SSH::Buffer.new(read_available(4))
        length = packet.read_long
        Net::SSH::Packet.new(read_available(length))
      end
    end

    # An extension to Net::SSH::Connection::Channel. Facilitates unit testing.
    module Channel
      def self.included(base) #:nodoc:
        base.send :alias_method, :send_data_for_real, :send_data
        base.send :alias_method, :send_data, :send_data_for_test
      end

      # The testing version of Net::SSH::Connection::Channel#send_data. Calls
      # the original implementation, and then immediately enqueues the data for
      # output so that scripted sends are properly interpreted as discrete
      # (rather than concatenated) data packets.
      def send_data_for_test(data)
        send_data_for_real(data)
        enqueue_pending_output
      end
    end

    # An extension to the built-in ::IO class. Simply redefines IO.select
    # so that it can be scripted in Net::SSH unit tests.
    module IO
      def self.included(base) #:nodoc:
        base.extend(ClassMethods)
      end

      module ClassMethods
        def self.extended(obj) #:nodoc:
          class <<obj
            alias_method :select_for_real, :select
            alias_method :select, :select_for_test
          end
        end

        # The testing version of ::IO.select. Assumes that all readers,
        # writers, and errors arrays are either nil, or contain only objects
        # that mix in Net::SSH::Test::Extensions::BufferedIo.
        def select_for_test(readers=nil, writers=nil, errors=nil, wait=nil)
          ready_readers = Array(readers).select { |r| r.select_for_read? }
          ready_writers = Array(writers).select { |r| r.select_for_write? }
          ready_errors  = Array(errors).select  { |r| r.select_for_error? }

          if ready_readers.any? || ready_writers.any? || ready_errors.any?
            return [ready_readers, ready_writers, ready_errors]
          end

          processed = 0
          Array(readers).each do |reader|
            processed += 1 if reader.idle!
          end

          raise "no readers were ready for reading, and none had any incoming packets" if processed == 0
        end
      end
    end
  end

end; end; end

Net::SSH::BufferedIo.send(:include, Net::SSH::Test::Extensions::BufferedIo)
Net::SSH::Transport::PacketStream.send(:include, Net::SSH::Test::Extensions::PacketStream)
Net::SSH::Connection::Channel.send(:include, Net::SSH::Test::Extensions::Channel)
IO.send(:include, Net::SSH::Test::Extensions::IO)
