require 'test_helper'
class PassThruDecompressorTest < MiniTest::Test
  include DecompressorTests

  def setup
    super
    @file = File.new(TEST_FILE)
    @decompressor = ::Zip::PassThruDecompressor.new(@file, File.size(TEST_FILE))
  end

  def teardown
    @file.close
  end
end
