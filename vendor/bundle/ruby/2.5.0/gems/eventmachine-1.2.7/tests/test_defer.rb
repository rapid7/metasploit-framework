require 'em_test_helper'

class TestDefer < Test::Unit::TestCase

  def test_defers
    n = 0
    n_times = 20
    EM.run {
      n_times.times {
        work_proc = proc { n += 1 }
        callback = proc { EM.stop if n == n_times }
        EM.defer work_proc, callback
      }
    }
    assert_equal( n, n_times )
  end

  def test_errbacks
    iterations = 20
    callback_parameter = rand(100)
    callback_parameters = []
    callback_op = proc { callback_parameter }
    callback = proc { |result| callback_parameters << result }
    errback_parameter = Exception.new
    errback_parameters = []
    errback_op = proc { raise errback_parameter }
    errback = proc { |error| errback_parameters << error }
    EventMachine.run do
      (1..iterations).each { |index| EventMachine.defer(index.even? ? callback_op : errback_op, callback, errback) }
      EventMachine.add_periodic_timer(0.1) { EventMachine.stop if EventMachine.defers_finished? }
    end
    assert_equal(callback_parameters.select { |parameter| parameter == callback_parameter }.length, iterations * 0.5)
    assert_equal(errback_parameters.select{ |parameter| parameter == errback_parameter }.length, iterations * 0.5)
  end
end
