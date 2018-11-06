# frozen_string_literal: true
require "benchmark"
require 'lib/yard'

def format_args_regex(object)
  if object.signature
    object.signature[/#{Regexp.quote object.name.to_s}\s*(.*)/, 1]
  else
    ""
  end
end

def format_args_parameters(object)
  if !object.parameters.empty?
    args = object.parameters.map {|n, v| v ? "#{n} = #{v}" : n.to_s }.join(", ")
    "(#{args})"
  else
    ""
  end
end

YARD::Registry.load
$object = YARD::Registry.at('YARD::Generators::Base#G')

log.puts "regex:  " + format_args_regex($object)
log.puts "params: " + format_args_parameters($object)
log.puts

TIMES = 100_000
Benchmark.bmbm do |x|
  x.report("regex")      { TIMES.times { format_args_regex($object) } }
  x.report("parameters") { TIMES.times { format_args_parameters($object) } }
end

=begin LAST RUN Jun 23 2008
regex:  (generator, opts = {})
params: (generator, opts = {})

Rehearsal ----------------------------------------------
regex        1.270000   0.020000   1.290000 (  1.294558)
parameters   0.690000   0.000000   0.690000 (  0.693324)
------------------------------------- total: 1.980000sec

                 user     system      total        real
regex        1.260000   0.010000   1.270000 (  1.268214)
parameters   0.670000   0.000000   0.670000 (  0.679114)
=end
