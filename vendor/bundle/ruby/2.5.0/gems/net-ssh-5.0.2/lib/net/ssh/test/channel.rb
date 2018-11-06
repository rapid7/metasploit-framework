module Net 
  module SSH 
    module Test

      # A mock channel, used for scripting actions in tests. It wraps a
      # Net::SSH::Test::Script instance, and delegates to it for the most part.
      # This class has little real functionality on its own, but rather acts as
      # a convenience for scripting channel-related activity for later comparison
      # in a unit test.
      #
      #   story do |session|
      #     channel = session.opens_channel
      #     channel.sends_exec "ls"
      #     channel.gets_data "result of ls"
      #     channel.gets_extended_data "some error coming from ls"
      #     channel.gets_close
      #     channel.sends_close
      #   end
      class Channel
        # The Net::SSH::Test::Script instance employed by this mock channel.
        attr_reader :script
    
        # Sets the local-id of this channel object (the id assigned by the client).
        attr_writer :local_id
    
        # Sets the remote-id of this channel object (the id assigned by the mock-server).
        attr_writer :remote_id
    
        # Creates a new Test::Channel instance on top of the given +script+ (which
        # must be a Net::SSH::Test::Script instance).
        def initialize(script)
          @script = script
          @local_id = @remote_id = nil
        end
    
        # Returns the local (client-assigned) id for this channel, or a Proc object
        # that will return the local-id later if the local id has not yet been set.
        # (See Net::SSH::Test::Packet#instantiate!.)
        def local_id
          @local_id || Proc.new { @local_id or raise "local-id has not been set yet!" }
        end
    
        # Returns the remote (server-assigned) id for this channel, or a Proc object
        # that will return the remote-id later if the remote id has not yet been set.
        # (See Net::SSH::Test::Packet#instantiate!.)
        def remote_id
          @remote_id || Proc.new { @remote_id or raise "remote-id has not been set yet!" }
        end
    
        # Because adjacent calls to #gets_data will sometimes cause the data packets
        # to be concatenated (causing expectations in tests to fail), you may
        # need to separate those calls with calls to #inject_remote_delay! (which
        # essentially just mimics receiving an empty data packet):
        #
        #   channel.gets_data "abcdefg"
        #   channel.inject_remote_delay!
        #   channel.gets_data "hijklmn"
        def inject_remote_delay!
          gets_data("")
        end
    
        # Scripts the sending of an "exec" channel request packet to the mock 
        # server. If +reply+ is true, then the server is expected to reply to the
        # request, otherwise no response to this request will be sent. If +success+
        # is +true+, then the request will be successful, otherwise a failure will
        # be scripted.
        #
        #   channel.sends_exec "ls -l"
        def sends_exec(command, reply=true, success=true)
          script.sends_channel_request(self, "exec", reply, command, success)
        end
    
        # Scripts the sending of a "subsystem" channel request packet to the mock
        # server. See #sends_exec for a discussion of the meaning of the +reply+
        # and +success+ arguments.
        #
        #   channel.sends_subsystem "sftp"
        def sends_subsystem(subsystem, reply=true, success=true)
          script.sends_channel_request(self, "subsystem", reply, subsystem, success)
        end
    
        # Scripts the sending of a data packet across the channel.
        #
        #   channel.sends_data "foo"
        def sends_data(data)
          script.sends_channel_data(self, data)
        end
    
        # Scripts the sending of an EOF packet across the channel.
        #
        #   channel.sends_eof
        def sends_eof
          script.sends_channel_eof(self)
        end
    
        # Scripts the sending of a "channel close" packet across the channel.
        #
        #   channel.sends_close
        def sends_close
          script.sends_channel_close(self)
        end
    
        # Scripts the sending of a "request pty" request packet across the channel.
        #
        #   channel.sends_request_pty
        def sends_request_pty
          script.sends_channel_request_pty(self)
        end
    
        # Scripts the reception of a channel data packet from the remote end.
        #
        #   channel.gets_data "bar"
        def gets_data(data)
          script.gets_channel_data(self, data)
        end
    
        # Scripts the reception of a channel extended data packet from the remote
        # end.
        #
        #   channel.gets_extended_data "whoops"
        def gets_extended_data(data)
          script.gets_channel_extended_data(self, data)
        end
    
        # Scripts the reception of an "exit-status" channel request packet.
        #
        #   channel.gets_exit_status(127)
        def gets_exit_status(status=0)
          script.gets_channel_request(self, "exit-status", false, status)
        end
    
        # Scripts the reception of an EOF packet from the remote end.
        #
        #   channel.gets_eof
        def gets_eof
          script.gets_channel_eof(self)
        end
    
        # Scripts the reception of a "channel close" packet from the remote end.
        #
        #   channel.gets_close
        def gets_close
          script.gets_channel_close(self)
        end
      end

    end
  end
end