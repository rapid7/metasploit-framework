require 'em_test_helper'

class TestSomeExceptions < Test::Unit::TestCase
  class DoomedConnectionError < StandardError
  end
  class DoomedConnection < EventMachine::Connection
    def unbind
      raise DoomedConnectionError
    end
  end

  # Read the commentary in EM#run.
  # This test exercises the ensure block in #run that makes sure
  # EM#release_machine gets called even if an exception is
  # thrown within the user code. Without the ensured call to release_machine,
  # the second call to EM#run will fail with a C++ exception
  # because the machine wasn't cleaned up properly.

  def test_a
    assert_raises(RuntimeError) {
      EM.run {
      raise "some exception"
    }
    }
  end

  def test_b
    assert_raises(RuntimeError) {
      EM.run {
      raise "some exception"
    }
    }
  end

  def test_exception_on_unbind
    assert_raises(DoomedConnectionError) {
      EM.run {
      EM.connect("localhost", 8888, DoomedConnection)
    }
    }
  end

end
