$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'fssm'

require 'rubygems'
require 'ruby-prof'

$test_path  = FSSM::Pathname.new('..').expand_path
$test_files = FSSM::Pathname.glob(File.join($test_path, '**', '*'))

RubyProf.start
RubyProf.pause

cache = FSSM::Tree::Cache.new

5000.times do |num|
  iteration = "%-5d" % (num + 1)
  print "iteration #{iteration}"

  print '!'
  RubyProf.resume
  cache.unset($test_path)
  RubyProf.pause
  print '!'

  $test_files.each do |fn|
    print '.'
    RubyProf.resume
    cache.set(fn)
    RubyProf.pause
  end

  print "\n\n"
end

result  = RubyProf.stop
output  = File.new('prof.html', 'w+')

printer = RubyProf::GraphHtmlPrinter.new(result)
printer.print(output, :min_percent => 1)
