require 'minitest/autorun'
require 'bit-struct'

class Test_Endian < Minitest::Test
  class Endian < BitStruct
    unsigned  :f_big,       32,   :endian => :big
    unsigned  :f_little,    32,   :endian => :little
    unsigned  :f_native,    32,   :endian => :native
    unsigned  :f_network,   32,   :endian => :network
  end

  attr_reader :bs

  def setup
    @bs = Endian.new
    bs.f_big = bs.f_little = bs.f_native = bs.f_network = 0x01020304
  end

  def test_readers
    assert_equal(0x01020304, bs.f_big)
    assert_equal(0x01020304, bs.f_little)
    assert_equal(0x01020304, bs.f_native)
    assert_equal(0x01020304, bs.f_network)
  end

  def test_writers
    bs.fields.each do |field|
      byte_offset = field.offset / 8
      valstr = bs.to_s[byte_offset, 4]
      case field.options[:endian]
      when :big, :network
        assert_equal("\01\02\03\04", valstr)
      when :little
        assert_equal("\04\03\02\01", valstr)
      when :native
      end
    end
  end
end
