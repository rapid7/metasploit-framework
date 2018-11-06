# frozen_string_literal: true
require "benchmark"

files = Dir.glob(File.dirname(__FILE__) + '/../lib/**/*.rb').join(" ")
Benchmark.bmbm do |x|
  x.report("rdoc") { `rm -rf rdoc && rdoc -q -o rdoc #{files} && rm -rf rdoc` }
  x.report("yardoc") { `rm -rf yard && ./bin/yardoc -q -o yard #{files} && rm -rf yard` }
  x.report("yardoc-cached") { `rm -rf yard && ./bin/yardoc -c -q -o yard #{files} && rm -rf yard` }
  x.report("yardoc-legacy") { `rm -rf yard && ./bin/yardoc --legacy -q -o yard #{files} && rm -rf yard` }
  x.report("yardoc-legacy-cached") { `rm -rf yard && ./bin/yardoc --legacy -c -q -o yard #{files} && rm -rf yard` }
end
