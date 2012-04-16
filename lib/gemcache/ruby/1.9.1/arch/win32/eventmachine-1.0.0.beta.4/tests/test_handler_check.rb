require 'em_test_helper'

class TestHandlerCheck < Test::Unit::TestCase

  class Foo < EM::Connection; end;
  module TestModule; end;

  def test_with_correct_class
    assert_nothing_raised do
      EM.run {
        EM.connect("127.0.0.1", 80, Foo)
        EM.stop_event_loop
      }
    end
  end

  def test_with_incorrect_class
    assert_raise(ArgumentError) do
      EM.run {
        EM.connect("127.0.0.1", 80, String)
        EM.stop_event_loop
      }
    end
  end

  def test_with_module
    assert_nothing_raised do
      EM.run {
        EM.connect("127.0.0.1", 80, TestModule)
        EM.stop_event_loop
      }
    end
  end

end