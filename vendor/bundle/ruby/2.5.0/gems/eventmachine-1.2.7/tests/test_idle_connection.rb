require 'em_test_helper'

class TestIdleConnection < Test::Unit::TestCase
  def setup
    @port = next_port
  end

  def test_idle_time
    omit_if(!EM.respond_to?(:get_idle_time))

    a, b = nil, nil
    EM.run do
      EM.start_server '127.0.0.1', @port, Module.new
      conn = EM.connect '127.0.0.1', @port
      EM.add_timer(0.3) do
        a = conn.get_idle_time
        conn.send_data 'a'
        EM.next_tick do
          EM.next_tick do
            b = conn.get_idle_time
            conn.close_connection
            EM.stop
          end
        end
      end
    end

    assert_in_delta 0.3, a, 0.1
    assert_in_delta 0, b, 0.1
  end
end
