# frozen_string_literal: true
require 'pathname'
require "benchmark"
require File.dirname(__FILE__) + '/../lib/yard'

pathobj = Pathname.new("a/b/c")
strobj  = "a/b/c"

TIMES = 1_000

log.puts "join:"
Benchmark.bmbm do |x|
  x.report("pathname") { TIMES.times { Pathname.new("a/b/c").join("d", "e", "f") } }
  x.report("string  ") { TIMES.times { File.join("a/b/c", "d", "e", "f") } }
  x.report("pathname-sameobject") { TIMES.times { pathobj.join("d", "e", "f") } }
  x.report("string-sameobject  ") { TIMES.times { File.join(strobj, "d", "e", "f") } }
end

log.puts
log.puts
log.puts "cleanpath:"
Benchmark.bmbm do |x|
  x.report("pathname") { TIMES.times { Pathname.new("a/b//.././c").cleanpath } }
  x.report("string  ") { TIMES.times { File.cleanpath("a/b//.././c") } }
end

__END__
join:
Rehearsal -------------------------------------------------------
pathname              0.330000   0.020000   0.350000 (  0.353481)
string                0.010000   0.000000   0.010000 (  0.001390)
pathname-sameobject   0.360000   0.020000   0.380000 (  0.384473)
string-sameobject     0.000000   0.000000   0.000000 (  0.001187)
---------------------------------------------- total: 0.740000sec

                          user     system      total        real
pathname              0.330000   0.020000   0.350000 (  0.350820)
string                0.000000   0.000000   0.000000 (  0.001055)
pathname-sameobject   0.330000   0.010000   0.340000 (  0.346949)
string-sameobject     0.000000   0.000000   0.000000 (  0.001141)


cleanpath:
Rehearsal --------------------------------------------
pathname   0.060000   0.000000   0.060000 (  0.059767)
string     0.010000   0.000000   0.010000 (  0.013775)
----------------------------------- total: 0.070000sec

               user     system      total        real
pathname   0.060000   0.000000   0.060000 (  0.059697)
string     0.020000   0.000000   0.020000 (  0.013624)