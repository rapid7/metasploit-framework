require 'minitest/autorun'
require 'bit-struct'

class Test_Vector < Minitest::Test
  class Packet < BitStruct
    unsigned :stuff, 32, "whatever"

    vector :v, "a vector", :length => 5 do
      unsigned :x,  16
      signed   :y,  32
    end

    unsigned :other, 16, "other stuff"
  end

  attr_reader :pkt

  def setup
    @pkt = Packet.new
  end

  def test_length
    assert_equal(Packet.round_byte_length, pkt.length)
  end

  def test_writers
    assert_equal(pkt.v[2].x, 0)
    v = pkt.v
      xy = v[2]
        xy.x = 3
        xy.y = -4
      v[2] = xy
    assert_equal(pkt.v[2].x, 0)
    pkt.v = v
    assert_equal(pkt.v[2].x, 3)
    assert_equal(pkt.v[2].y, -4)
  end
end
