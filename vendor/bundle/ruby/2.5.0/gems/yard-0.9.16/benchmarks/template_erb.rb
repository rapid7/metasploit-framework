# frozen_string_literal: true
require "benchmark"
require File.join(File.dirname(__FILE__), '..', 'lib', 'yard')

YARD::Registry.load_yardoc(File.join(File.dirname(__FILE__), '..', '.yardoc'))
obj = YARD::Registry.at("YARD::CodeObjects::Base")

TIMES = 3
Benchmark.bm do |x|
  x.report("trim-line") { TIMES.times { obj.format(:format => :html) } }
  module YARD
    module Templates
      module Template
        def erb(section, &block)
          erb = ERB.new(cache(section))
          erb.filename = cache_filename(section).to_s
          erb.result(binding, &block)
        end
      end
    end
  end
  x.report("no-trim  ") { TIMES.times { obj.format(:format => :html) } }
end
