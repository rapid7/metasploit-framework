# frozen_string_literal: true
require "benchmark"

TIMES = 10
Benchmark.bmbm do |x|
  x.report("ri") { TIMES.times { `ri -T YARD::Tags::Library` } }
  x.report("yri") { TIMES.times { `./bin/yri -T YARD::Tags::Library` } }
end

__END__

Rehearsal ---------------------------------------
ri    0.000000   0.020000   6.880000 (  6.929591)
yri   0.000000   0.000000   1.060000 (  1.074840)
------------------------------ total: 7.940000sec

          user     system      total        real
ri    0.000000   0.020000   6.850000 (  6.871660)
yri   0.000000   0.010000   1.060000 (  1.067585)
