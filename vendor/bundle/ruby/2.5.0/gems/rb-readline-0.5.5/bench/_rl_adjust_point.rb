$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../lib/"
require 'rbreadline'
require 'benchmark'

N = 100_000

Benchmark.bmbm do |x|
  x.report do
    N.times { RbReadline._rl_adjust_point("a", 0) }
  end
  x.report do
    N.times { RbReadline._rl_adjust_point("a", 1) }
  end
  x.report do
    N.times { RbReadline._rl_adjust_point("aaaaaaaaaaaaaaaaaaaaa", 0) }
  end
  x.report do
    N.times { RbReadline._rl_adjust_point("aaaaaaaaaaaaaaaaaaaaa", 40) }
  end
  x.report do
    N.times { RbReadline._rl_adjust_point("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0) }
  end
  x.report do
    N.times { RbReadline._rl_adjust_point("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 40) }
  end
end
