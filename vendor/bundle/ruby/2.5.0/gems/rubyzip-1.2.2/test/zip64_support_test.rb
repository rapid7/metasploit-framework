require 'test_helper'

class Zip64SupportTest < MiniTest::Test
  TEST_FILE = File.join(File.dirname(__FILE__), 'data', 'zip64-sample.zip')

  def test_open_zip64_file
    zip_file = ::Zip::File.open(TEST_FILE)
    assert(!zip_file.nil?)
    assert(zip_file.entries.count == 2)
    test_rb = zip_file.entries.find { |x| x.name == 'test.rb' }
    assert(test_rb.size == 482)
    assert(test_rb.compressed_size == 229)
  end
end
