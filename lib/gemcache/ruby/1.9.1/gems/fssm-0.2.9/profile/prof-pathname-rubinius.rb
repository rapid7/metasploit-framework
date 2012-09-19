$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'pathname'

$test_path  = "#{Pathname.new('..').expand_path}"
$iterations = 900000

if ARGV.first == 'native'
  puts "Using native Pathname"

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

  $iterations.times do |num|
    p        = ::Pathname.new($test_path)
    segments = p.segments
  end
else
  puts "Using FSSM::Pathname"

  require 'fssm'

  $iterations.times do |num|
    p        = FSSM::Pathname.new($test_path)
    segments = p.segments
  end
end
