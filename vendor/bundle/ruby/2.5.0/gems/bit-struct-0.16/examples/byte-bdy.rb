# an example where a field may crosse one or two byte boundaries
#
# try with arguments like 4, 12, and 13 to see the difference
#
# based on test case from Jon Hart

require 'bit-struct'
class Foo < BitStruct
  unsigned :a, 4
  unsigned :b, 8
  unsigned :c, (ARGV[0] || (raise "USAGE: #{$0} bits")).to_i
end

puts Foo.describe

foo = Foo.new
p foo
p foo.unpack("B*").first.scan(/\d{8,8}/)
puts

foo.c = 3123
p foo
p foo.unpack("B*").first.scan(/\d{8,8}/)
puts

foo.c = (2**(ARGV[0].to_i)-1)
p foo
p foo.unpack("B*").first.scan(/\d{8,8}/)
puts

