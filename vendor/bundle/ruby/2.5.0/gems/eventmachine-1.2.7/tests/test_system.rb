# coding: utf-8
require 'em_test_helper'

class TestSystem < Test::Unit::TestCase
  def setup
    @filename = File.expand_path("../я манал dump.txt", __FILE__)
    @test_data = 'a' * 100
    File.open(@filename, 'w'){|f| f.write(@test_data)}
  end

  def test_system
    omit_if(windows?)

    result = nil
    status = nil
    EM.run {
      EM.system('cat', @filename){|out, state|
        result = out
        status = state.exitstatus
        EM.stop
      }
    }
    assert_equal(0, status)
    assert_equal(@test_data, result)
  end

  def test_system_with_string
    omit_if(windows?)

    result = nil
    status = nil
    EM.run {
      EM.system("cat '#@filename'"){|out, state|
        result = out
        status = state.exitstatus
        EM.stop
      }
    }
    assert_equal(0, status)
    assert_equal(@test_data, result)
  end

  def teardown
    File.unlink(@filename)
  end
end
