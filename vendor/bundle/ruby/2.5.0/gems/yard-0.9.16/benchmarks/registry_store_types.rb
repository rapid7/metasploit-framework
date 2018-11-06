# frozen_string_literal: true
require 'benchmark'
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

def parse_and_select_objects
  YARD::Registry.load_yardoc(File.join(File.dirname(__FILE__), '..', '.yardoc'))
  YARD::Registry.load_all
  $paths = []
  4.times { $paths << YARD::Registry.paths[rand(YARD::Registry.paths.size)] }

  $regular_registry = {}
  $types_registry = {}
  YARD::Registry.all.each do |object|
    $regular_registry[object.path] = object
    ($types_registry[object.type] ||= {})[object.path] = object
  end
end

def run_lookup
  $paths.select {|path| $regular_registry[path] }
end

def run_lookup_with_types
  $paths.select {|path| $types_registry.values.find {|list| list[path] } }
end

TIMES = 100_000

parse_and_select_objects
p $paths
Benchmark.bmbm do |x|
  x.report("normal") { TIMES.times { run_lookup } }
  x.report("types")  { TIMES.times { run_lookup_with_types } }
end

__END__
# Run on March 22 2012
["YARD::Parser::Ruby::Legacy::RubyToken::TkUnknownChar#initialize",
  "YARD::Parser::C::CParser#enumerator",
  "YARD::CodeObjects::ClassObject#inherited_meths",
  "YARD::Parser::C::Statement#source="]
Rehearsal ----------------------------------------------
normal       0.180000   0.000000   0.180000 (  0.182640)
types        1.150000   0.010000   1.160000 (  1.160219)
------------------------------------- total: 1.340000sec

                 user     system      total        real
normal       0.170000   0.000000   0.170000 (  0.165621)
types        1.140000   0.000000   1.140000 (  1.142269)
