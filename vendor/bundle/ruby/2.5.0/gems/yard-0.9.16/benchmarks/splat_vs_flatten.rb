# frozen_string_literal: true
require "benchmark"

# To prove that flattening a small list is not significantly slower than
# calling *list (used to get around create_tag list issue)
$a = "FOO BAR BAZ"
def foo(*args) args.last.inspect end

TESTS = 10_000
Benchmark.bmbm do |x|
  x.report("splat") { TESTS.times { foo(*$a) } }
  x.report("flatten") { TESTS.times { foo(*[$a].flatten) } }
end
