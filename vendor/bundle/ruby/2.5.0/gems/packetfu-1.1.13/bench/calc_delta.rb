require 'benchmark'
require 'pp'

before = ARGV.shift
after = ARGV.shift

fio = File.open(before)
before_data = Marshal.load(fio)
fio.close

fio = File.open(after)
after_data = Marshal.load(fio)
fio.close

before_data.each_with_index do |data, i|
  puts (data.total / after_data[i].total)
end
