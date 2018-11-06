require 'test_helper'

class PassThruCompressorTest < MiniTest::Test
  include CrcTest

  def test_size
    File.open('test/data/generated/dummy.txt', 'wb') do |file|
      compressor = ::Zip::PassThruCompressor.new(file)

      assert_equal(0, compressor.size)

      t1 = 'hello world'
      t2 = ''
      t3 = 'bingo'

      compressor << t1
      assert_equal(compressor.size, t1.size)

      compressor << t2
      assert_equal(compressor.size, t1.size + t2.size)

      compressor << t3
      assert_equal(compressor.size, t1.size + t2.size + t3.size)
    end
  end

  def test_crc
    run_crc_test(::Zip::PassThruCompressor)
  end
end
