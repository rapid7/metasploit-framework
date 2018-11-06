require 'net/ssh/test/channel'
require 'net/ssh/test/local_packet'
require 'net/ssh/test/remote_packet'

module Net 
  module SSH 
    module Test

      # Represents a sequence of scripted events that identify the behavior that
      # a test expects. Methods named "sends_*" create events for packets being
      # sent from the local to the remote host, and methods named "gets_*" create
      # events for packets being received by the local from the remote host.
      #
      # A reference to a script. is generally obtained in a unit test via the
      # Net::SSH::Test#story helper method:
      #
      #   story do |script|
      #     channel = script.opens_channel
      #     ...
      #   end
      class Script
        # The list of scripted events. These will be Net::SSH::Test::LocalPacket
        # and Net::SSH::Test::RemotePacket instances.
        attr_reader :events
    
        # Create a new, empty script.
        def initialize
          @events = []
        end
    
        # Scripts the opening of a channel by adding a local packet sending the
        # channel open request, and if +confirm+ is true (the default), also
        # adding a remote packet confirming the new channel.
        #
        # A new Net::SSH::Test::Channel instance is returned, which can be used
        # to script additional channel operations.
        def opens_channel(confirm=true)
          channel = Channel.new(self)
          channel.remote_id = 5555
    
          events << LocalPacket.new(:channel_open) { |p| channel.local_id = p[:remote_id] }
    
          events << RemotePacket.new(:channel_open_confirmation, channel.local_id, channel.remote_id, 0x20000, 0x10000) if confirm
    
          channel
        end
    
        # A convenience method for adding an arbitrary local packet to the events
        # list.
        def sends(type, *args, &block)
          events << LocalPacket.new(type, *args, &block)
        end
    
        # A convenience method for adding an arbitrary remote packet to the events
        # list.
        def gets(type, *args)
          events << RemotePacket.new(type, *args)
        end
    
        # Scripts the sending of a new channel request packet to the remote host.
        # +channel+ should be an instance of Net::SSH::Test::Channel. +request+
        # is a string naming the request type to send, +reply+ is a boolean
        # indicating whether a response to this packet is required , and +data+
        # is any additional request-specific data that this packet should send.
        # +success+ indicates whether the response (if one is required) should be
        # success or failure. If +data+ is an array it will be treated as multiple
        # data.
        #
        # If a reply is desired, a remote packet will also be queued, :channel_success
        # if +success+ is true, or :channel_failure if +success+ is false.
        #
        # This will typically be called via Net::SSH::Test::Channel#sends_exec or
        # Net::SSH::Test::Channel#sends_subsystem.
        def sends_channel_request(channel, request, reply, data, success=true)
          if data.is_a? Array
            events << LocalPacket.new(:channel_request, channel.remote_id, request, reply, *data)
          else
            events << LocalPacket.new(:channel_request, channel.remote_id, request, reply, data)
          end
          if reply
            if success
              events << RemotePacket.new(:channel_success, channel.local_id)
            else
              events << RemotePacket.new(:channel_failure, channel.local_id)
            end
          end
        end
    
        # Scripts the sending of a channel data packet. +channel+ must be a
        # Net::SSH::Test::Channel object, and +data+ is the (string) data to
        # expect will be sent.
        #
        # This will typically be called via Net::SSH::Test::Channel#sends_data.
        def sends_channel_data(channel, data)
          events << LocalPacket.new(:channel_data, channel.remote_id, data)
        end
    
        # Scripts the sending of a channel EOF packet from the given
        # Net::SSH::Test::Channel +channel+. This will typically be called via
        # Net::SSH::Test::Channel#sends_eof.
        def sends_channel_eof(channel)
          events << LocalPacket.new(:channel_eof, channel.remote_id)
        end
    
        # Scripts the sending of a channel close packet from the given
        # Net::SSH::Test::Channel +channel+. This will typically be called via
        # Net::SSH::Test::Channel#sends_close.
        def sends_channel_close(channel)
          events << LocalPacket.new(:channel_close, channel.remote_id)
        end
    
        # Scripts the sending of a channel request pty packets from the given
        # Net::SSH::Test::Channel +channel+. This will typically be called via
        # Net::SSH::Test::Channel#sends_request_pty.
        def sends_channel_request_pty(channel)
          data = ['pty-req', false]
          data += Net::SSH::Connection::Channel::VALID_PTY_OPTIONS.merge(modes: "\0").values
          events << LocalPacket.new(:channel_request, channel.remote_id, *data)
        end
    
        # Scripts the reception of a channel data packet from the remote host by
        # the given Net::SSH::Test::Channel +channel+. This will typically be
        # called via Net::SSH::Test::Channel#gets_data.
        def gets_channel_data(channel, data)
          events << RemotePacket.new(:channel_data, channel.local_id, data)
        end
    
        # Scripts the reception of a channel extended data packet from the remote
        # host by the given Net::SSH::Test::Channel +channel+. This will typically
        # be called via Net::SSH::Test::Channel#gets_extended_data.
        #
        # Currently the only extended data type is stderr == 1.
        def gets_channel_extended_data(channel, data)
          events << RemotePacket.new(:channel_extended_data, channel.local_id, 1, data)
        end
    
        # Scripts the reception of a channel request packet from the remote host by
        # the given Net::SSH::Test::Channel +channel+. This will typically be
        # called via Net::SSH::Test::Channel#gets_exit_status.
        def gets_channel_request(channel, request, reply, data)
          events << RemotePacket.new(:channel_request, channel.local_id, request, reply, data)
        end
    
        # Scripts the reception of a channel EOF packet from the remote host by
        # the given Net::SSH::Test::Channel +channel+. This will typically be
        # called via Net::SSH::Test::Channel#gets_eof.
        def gets_channel_eof(channel)
          events << RemotePacket.new(:channel_eof, channel.local_id)
        end
    
        # Scripts the reception of a channel close packet from the remote host by
        # the given Net::SSH::Test::Channel +channel+. This will typically be
        # called via Net::SSH::Test::Channel#gets_close.
        def gets_channel_close(channel)
          events << RemotePacket.new(:channel_close, channel.local_id)
        end
    
        # By default, removes the next event in the list and returns it. However,
        # this can also be used to non-destructively peek at the next event in the
        # list, by passing :first as the argument.
        #
        #   # remove the next event and return it
        #   event = script.next
        #
        #   # peek at the next event
        #   event = script.next(:first)
        def next(mode=:shift)
          events.send(mode)
        end
    
        # Compare the given packet against the next event in the list. If there is
        # no next event, an exception will be raised. This is called by
        # Net::SSH::Test::Extensions::PacketStream#test_enqueue_packet.
        def process(packet)
          event = events.shift or raise "end of script reached, but got a packet type #{packet.read_byte}"
          event.process(packet)
        end
      end

    end
  end
end