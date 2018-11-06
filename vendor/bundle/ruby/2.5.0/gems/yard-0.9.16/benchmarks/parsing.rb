# frozen_string_literal: true
require "benchmark"
require 'yard'
require 'logger'

PATH_ORDER = [
  'lib/yard/autoload.rb',
  'lib/yard/code_objects/base.rb',
  'lib/yard/code_objects/namespace_object.rb',
  'lib/yard/handlers/base.rb',
  'lib/yard/generators/helpers/*.rb',
  'lib/yard/generators/base.rb',
  'lib/yard/generators/method_listing_generator.rb',
  'lib/yard/serializers/base.rb',
  'lib/**/*.rb'
]

Benchmark.bmbm do |x|
  x.report("parse in order") { YARD::Registry.clear; YARD.parse PATH_ORDER, [], Logger::ERROR }
  x.report("parse") { YARD::Registry.clear; YARD.parse 'lib/**/*.rb', [], Logger::ERROR }
end

=begin
load_order branch (2008-06-07):

Rehearsal --------------------------------------------------
parse in order   6.510000   0.050000   6.560000 (  6.563223)
parse            6.300000   0.040000   6.340000 (  6.362272)
---------------------------------------- total: 12.900000sec

                     user     system      total        real
parse in order   6.310000   0.060000   6.370000 (  6.390945)
parse            6.300000   0.050000   6.350000 (  6.366709)


api_changes branch before merge (2008-06-07)

Rehearsal --------------------------------------------------
parse in order   6.330000   0.050000   6.380000 (  6.397552)
parse            6.380000   0.050000   6.430000 (  6.446954)
---------------------------------------- total: 12.810000sec

                     user     system      total        real
parse in order   6.320000   0.040000   6.360000 (  6.394460)
parse            6.040000   0.040000   6.080000 (  6.099738)
=end
