$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'eventmachine'
require 'socket'
require 'test/unit'

class TestPause < Test::Unit::TestCase
  TestHost = "127.0.0.1"
  TestPort = 9070

  def setup
    assert(!EM.reactor_running?)
  end

  def teardown
    assert(!EM.reactor_running?)
  end

  #-------------------------------------

  def test_pause_resume
    test = self
    server = nil

    s_rx = c_rx = 0

    EM.run do
      EM.start_server TestHost, TestPort, Module.new {
        define_method :post_init do
          server = self
        end

        define_method :receive_data do |data|
          s_rx += 1

          EM.add_periodic_timer(0.01) { send_data 'hi' }
          send_data 'hi'

          # pause server, now no outgoing data will actually
          # be sent and no more incoming data will be received
          pause
        end
      }

      c = EM.connect TestHost, TestPort, Module.new {
        define_method :receive_data do |data|
          c_rx += 1
        end
      }
      EM.add_periodic_timer(0.01) { c.send_data 'hi' }

      EM.add_timer(1) do
        test.assert_equal 1, s_rx
        test.assert_equal 0, c_rx
        test.assert server.paused?

        # resume server, queued outgoing and incoming data will be flushed
        server.resume

        test.assert ! server.paused?

        EM.add_timer(1) do
          test.assert server.paused?
          test.assert s_rx >= 2
          test.assert c_rx >= 1
          EM.stop_event_loop
        end
      end
    end
  end
end
