# encoding: utf-8
# frozen_string_literal: true
require 'benchmark'
require File.dirname(__FILE__) + '/../lib/yard'

$files = Dir[File.dirname(__FILE__) + '/../lib/**/*.rb'].map {|f| File.read(f) }
$files_rip = Dir[File.dirname(__FILE__) + '/../lib/**/*.rb'].map {|f| [File.read(f), f] }

TIMES = 2
Benchmark.bmbm do |x|
  x.report("rip-parser") { TIMES.times { $files_rip.each {|f| YARD::Parser::Ruby::RubyParser.parse(*f) } } }
  x.report("yard-parser  ") { TIMES.times { $files.each {|f| YARD::Parser::Ruby::Legacy::StatementList.new(f) } } }
end
