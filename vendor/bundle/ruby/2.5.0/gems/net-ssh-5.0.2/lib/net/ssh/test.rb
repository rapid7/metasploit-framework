require 'net/ssh/transport/session'
require 'net/ssh/connection/session'
require 'net/ssh/test/kex'
require 'net/ssh/test/socket'

module Net 
  module SSH

    # This module may be used in unit tests, for when you want to test that your
    # SSH state machines are really doing what you expect they are doing. You will
    # typically include this module in your unit test class, and then build a
    # "story" of expected sends and receives:
    #
    #   require 'minitest/autorun'
    #   require 'net/ssh/test'
    #
    #   class MyTest < Minitest::Test
    #     include Net::SSH::Test
    #
    #     def test_exec_via_channel_works
    #       story do |session|
    #         channel = session.opens_channel
    #         channel.sends_exec "ls"
    #         channel.gets_data "result of ls"
    #         channel.gets_close
    #         channel.sends_close
    #       end
    #
    #       assert_scripted do
    #         result = nil
    #
    #         connection.open_channel do |ch|
    #           ch.exec("ls") do |success|
    #             ch.on_data { |c, data| result = data }
    #             ch.on_close { |c| c.close }
    #           end
    #         end
    #
    #         connection.loop
    #         assert_equal "result of ls", result
    #       end
    #     end
    #   end
    #
    # See Net::SSH::Test::Channel and Net::SSH::Test::Script for more options.
    #
    # Note that the Net::SSH::Test system is rather finicky yet, and can be kind
    # of frustrating to get working. Any suggestions for improvement will be
    # welcome!
    module Test
      # If a block is given, yields the script for the test socket (#socket).
      # Otherwise, simply returns the socket's script. See Net::SSH::Test::Script.
      def story
        Net::SSH::Test::Extensions::IO.with_test_extension { yield socket.script if block_given? }
        return socket.script
      end
  
      # Returns the test socket instance to use for these tests (see
      # Net::SSH::Test::Socket).
      def socket(options={})
        @socket ||= Net::SSH::Test::Socket.new
      end
  
      # Returns the connection session (Net::SSH::Connection::Session) for use
      # in these tests. It is a fully functional SSH session, operating over
      # a mock socket (#socket).
      def connection(options={})
        @connection ||= Net::SSH::Connection::Session.new(transport(options), options)
      end
  
      # Returns the transport session (Net::SSH::Transport::Session) for use
      # in these tests. It is a fully functional SSH transport session, operating
      # over a mock socket (#socket).
      def transport(options={})
        @transport ||= Net::SSH::Transport::Session.new(
          options[:host] || "localhost",
          options.merge(kex: "test", host_key: "ssh-rsa", verify_host_key: false, proxy: socket(options))
        )
      end
  
      # First asserts that a story has been described (see #story). Then yields,
      # and then asserts that all items described in the script have been
      # processed. Typically, this is called immediately after a story has
      # been built, and the SSH commands being tested are then executed within
      # the block passed to this assertion.
      def assert_scripted
        raise "there is no script to be processed" if socket.script.events.empty?
        Net::SSH::Test::Extensions::IO.with_test_extension { yield }
        assert socket.script.events.empty?, "there should not be any remaining scripted events, but there are still #{socket.script.events.length} pending"
      end
    end

  end
end
