# frozen_string_literal: true
require File.dirname(__FILE__) + "/../lib/yard"
require "benchmark"
include YARD::CLI

class YARD::CLI::YRI
  def print_object(object) end
end

def remove_cache
  File.unlink(YRI::CACHE_FILE)
end

TIMES = 10
NAME = 'YARD'
remove_cache; YRI.run(NAME)
Benchmark.bmbm do |x|
  x.report("cache   ") { TIMES.times { YRI.run(NAME) } }
  x.report("no-cache") { TIMES.times { remove_cache; YRI.run(NAME) } }
end
