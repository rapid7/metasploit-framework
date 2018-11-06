require 'test_helper'
require 'zip/filesystem'

class ZipFsDirIteratorTest < MiniTest::Test
  FILENAME_ARRAY = %w[f1 f2 f3 f4 f5 f6]

  def setup
    @dirIt = ::Zip::FileSystem::ZipFsDirIterator.new(FILENAME_ARRAY)
  end

  def test_close
    @dirIt.close
    assert_raises(IOError, 'closed directory') do
      @dirIt.each { |e| p e }
    end
    assert_raises(IOError, 'closed directory') do
      @dirIt.read
    end
    assert_raises(IOError, 'closed directory') do
      @dirIt.rewind
    end
    assert_raises(IOError, 'closed directory') do
      @dirIt.seek(0)
    end
    assert_raises(IOError, 'closed directory') do
      @dirIt.tell
    end
  end

  def test_each
    # Tested through Enumerable.entries
    assert_equal(FILENAME_ARRAY, @dirIt.entries)
  end

  def test_read
    FILENAME_ARRAY.size.times do |i|
      assert_equal(FILENAME_ARRAY[i], @dirIt.read)
    end
  end

  def test_rewind
    @dirIt.read
    @dirIt.read
    assert_equal(FILENAME_ARRAY[2], @dirIt.read)
    @dirIt.rewind
    assert_equal(FILENAME_ARRAY[0], @dirIt.read)
  end

  def test_tell_seek
    @dirIt.read
    @dirIt.read
    pos = @dirIt.tell
    valAtPos = @dirIt.read
    @dirIt.read
    @dirIt.seek(pos)
    assert_equal(valAtPos, @dirIt.read)
  end
end
