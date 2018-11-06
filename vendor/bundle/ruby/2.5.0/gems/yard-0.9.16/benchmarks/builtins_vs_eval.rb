# frozen_string_literal: true
require 'benchmark'
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

TIMES = (ARGV[0] || 10_000).to_i

def bench_builtins(name)
  YARD::CodeObjects::BUILTIN_EXCEPTIONS_HASH.key? name
end

def bench_eval(name)
  eval(name).is_a?(Class)
rescue
  false
end

Benchmark.bmbm do |b|
  b.report("builtins PASS") { TIMES.times { YARD::CodeObjects::BUILTIN_EXCEPTIONS.each {|y| bench_builtins(y) } } }
  b.report("eval PASS") { TIMES.times { YARD::CodeObjects::BUILTIN_EXCEPTIONS.each {|y| bench_eval(y) } } }
  b.report("builtins FAIL") { TIMES.times { YARD::CodeObjects::BUILTIN_MODULES.each {|y| bench_builtins(y) } } }
  b.report("eval FAIL") { TIMES.times { YARD::CodeObjects::BUILTIN_MODULES.each {|y| bench_eval(y) } } }
  b.report("builtins ANY") { TIMES.times { YARD::CodeObjects::BUILTIN_CLASSES.each {|y| bench_builtins(y) } } }
  b.report("eval ANY") { TIMES.times { YARD::CodeObjects::BUILTIN_CLASSES.each {|y| bench_eval(y) } } }
end
