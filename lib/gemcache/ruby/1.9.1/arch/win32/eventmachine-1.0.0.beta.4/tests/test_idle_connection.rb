require 'em_test_helper'

class TestIdleConnection < Test::Unit::TestCase
  if EM.respond_to?(:get_idle_time)
    def test_idle_time
      EM.run{
        conn = EM.connect 'www.google.com', 80
        EM.add_timer(3){
          $idle_time = conn.get_idle_time
          conn.send_data "GET / HTTP/1.0\r\n\r\n"
          EM.next_tick{
            $idle_time_after_send = conn.get_idle_time
            conn.close_connection
            EM.stop
          }
        }
      }

      assert_in_delta 3, $idle_time, 0.2
      assert_equal 0, $idle_time_after_send
    end
  end
end
