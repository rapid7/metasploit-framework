$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'fssm'
require 'pathname'

require 'rubygems'
require 'ruby-prof'

$test_path  = "#{Pathname.new('..').expand_path}"
$iterations = 90000

class Pathname
  # original segments implementation I was using with
  # the plain ruby Pathname library.
  def segments
    prefix, names = split_names(@path)
    names.unshift(prefix) unless prefix.empty?
    names.shift if names[0] == '.'
    names
  end
end

core_result = Pathname.new($test_path).segments
fssm_result = FSSM::Pathname.new($test_path).segments
raise Exception, "#{core_result.inspect} != #{fssm_result.inspect}\nFSSM::Pathname is incompatible with Pathname" unless core_result == fssm_result

RubyProf.start
RubyProf.pause

$iterations.times do |num|
  iteration = "%-6d" % (num + 1)
  puts "FSSM::Pathname iteration #{iteration}"

  RubyProf.resume
  p        = FSSM::Pathname.new($test_path)
  segments = p.segments
  RubyProf.pause
end

puts "\nFSSM Pathname profile finished\n\n"

result  = RubyProf.stop
output  = File.new('prof-fssm-pathname.html', 'w+')

printer = RubyProf::GraphHtmlPrinter.new(result)
printer.print(output, :min_percent => 1)


RubyProf.start
RubyProf.pause

$iterations.times do |num|
  iteration = "%-6d" % (num + 1)
  puts "::Pathname iteration #{iteration}"

  RubyProf.resume
  p        = ::Pathname.new($test_path)
  segments = p.segments
  RubyProf.pause
end

puts "\nruby Pathname profile finished\n\n"

result  = RubyProf.stop
output  = File.new('prof-plain-pathname.html', 'w+')

printer = RubyProf::GraphHtmlPrinter.new(result)
printer.print(output, :min_percent => 1)
