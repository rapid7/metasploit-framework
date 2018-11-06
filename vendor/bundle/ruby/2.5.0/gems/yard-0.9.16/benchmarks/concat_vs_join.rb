# frozen_string_literal: true
require "benchmark"

STR1 = "Hello"
JOIN = "::"
STR2 = "World"

TESTS = 100_000
Benchmark.bmbm do |results|
  results.report("concat") { TESTS.times { "".concat(STR1).concat(JOIN).concat(STR2) } }
  results.report("add   ") { TESTS.times { STR1 + JOIN + STR2 } }
  results.report("join  ") { TESTS.times { [STR1, STR2].join(JOIN) } }
end
