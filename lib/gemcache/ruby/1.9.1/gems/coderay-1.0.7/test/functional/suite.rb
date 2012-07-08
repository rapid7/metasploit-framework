require 'test/unit'

$VERBOSE = $CODERAY_DEBUG = true
$:.unshift File.expand_path('../../../lib', __FILE__)
require 'coderay'

mydir = File.dirname(__FILE__)
suite = Dir[File.join(mydir, '*.rb')].
  map { |tc| File.basename(tc).sub(/\.rb$/, '') } - %w'suite for_redcloth'

puts "Running basic CodeRay #{CodeRay::VERSION} tests: #{suite.join(', ')}"

for test_case in suite
  load File.join(mydir, test_case + '.rb')
end
