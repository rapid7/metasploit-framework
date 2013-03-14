$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestErrorHandler < Test::Unit::TestCase
  def test_error_handler
    error = nil
    EM.error_handler{ |e|
      error = e
      EM.error_handler(nil)
      EM.stop
    }

    assert_nothing_raised do
      EM.run{
        EM.add_timer(0){
          raise 'test'
        }
      }
    end

    assert_equal error.class, RuntimeError
    assert_equal error.message, 'test'
  end

  def test_without_error_handler
    assert_raise RuntimeError do
      EM.run{
        EM.add_timer(0){
          raise 'test'
        }
      }
    end
  end
end
