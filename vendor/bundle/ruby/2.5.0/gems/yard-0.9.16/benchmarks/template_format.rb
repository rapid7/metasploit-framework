# frozen_string_literal: true
require "benchmark"
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

YARD::Registry.load_yardoc(File.join(File.dirname(__FILE__), '..', '.yardoc'))
obj = YARD::Registry.at("YARD::CodeObjects::Base")
log.puts Benchmark.measure { obj.format(:format => :html) }
