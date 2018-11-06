require 'simplecov'
require 'minitest/autorun'
require 'minitest/unit'
require 'fileutils'
require 'digest/sha1'
require 'zip'
require 'gentestfiles'

TestFiles.create_test_files
TestZipFile.create_test_zips

if defined? JRUBY_VERSION
  require 'jruby'
  JRuby.objectspace = true
end

::MiniTest.after_run do
  FileUtils.rm_rf('test/data/generated')
end

module IOizeString
  attr_reader :tell

  def read(count = nil)
    @tell ||= 0
    count = size unless count
    retVal = slice(@tell, count)
    @tell += count
    retVal
  end

  def seek(index, offset)
    @tell ||= 0
    case offset
    when IO::SEEK_END
      newPos = size + index
    when IO::SEEK_SET
      newPos = index
    when IO::SEEK_CUR
      newPos = @tell + index
    else
      raise 'Error in test method IOizeString::seek'
    end
    if newPos < 0 || newPos >= size
      raise Errno::EINVAL
    else
      @tell = newPos
    end
  end

  def reset
    @tell = 0
  end
end

module DecompressorTests
  # expects @refText, @refLines and @decompressor

  TEST_FILE = 'test/data/file1.txt'

  def setup
    @refText = ''
    File.open(TEST_FILE) { |f| @refText = f.read }
    @refLines = @refText.split($/)
  end

  def test_read_everything
    assert_equal(@refText, @decompressor.sysread)
  end

  def test_read_in_chunks
    chunkSize = 5
    while (decompressedChunk = @decompressor.sysread(chunkSize))
      assert_equal(@refText.slice!(0, chunkSize), decompressedChunk)
    end
    assert_equal(0, @refText.size)
  end

  def test_mixing_reads_and_produce_input
    # Just some preconditions to make sure we have enough data for this test
    assert(@refText.length > 1000)
    assert(@refLines.length > 40)

    assert_equal(@refText[0...100], @decompressor.sysread(100))

    assert(!@decompressor.input_finished?)
    buf = @decompressor.produce_input
    assert_equal(@refText[100...(100 + buf.length)], buf)
  end
end

module AssertEntry
  def assert_next_entry(filename, zis)
    assert_entry(filename, zis, zis.get_next_entry.name)
  end

  def assert_entry(filename, zis, entryName)
    assert_equal(filename, entryName)
    assert_entry_contents_for_stream(filename, zis, entryName)
  end

  def assert_entry_contents_for_stream(filename, zis, entryName)
    File.open(filename, 'rb') do |file|
      expected = file.read
      actual = zis.read
      if expected != actual
        if (expected && actual) && (expected.length > 400 || actual.length > 400)
          zipEntryFilename = entryName + '.zipEntry'
          File.open(zipEntryFilename, 'wb') { |entryfile| entryfile << actual }
          fail("File '#{filename}' is different from '#{zipEntryFilename}'")
        else
          assert_equal(expected, actual)
        end
      end
    end
  end

  def self.assert_contents(filename, aString)
    fileContents = ''
    File.open(filename, 'rb') { |f| fileContents = f.read }
    if fileContents != aString
      if fileContents.length > 400 || aString.length > 400
        stringFile = filename + '.other'
        File.open(stringFile, 'wb') { |f| f << aString }
        fail("File '#{filename}' is different from contents of string stored in '#{stringFile}'")
      else
        assert_equal(fileContents, aString)
      end
    end
  end

  def assert_stream_contents(zis, testZipFile)
    assert(!zis.nil?)
    testZipFile.entry_names.each do |entryName|
      assert_next_entry(entryName, zis)
    end
    assert_nil(zis.get_next_entry)
  end

  def assert_test_zip_contents(testZipFile)
    ::Zip::InputStream.open(testZipFile.zip_name) do |zis|
      assert_stream_contents(zis, testZipFile)
    end
  end

  def assert_entry_contents(zipFile, entryName, filename = entryName.to_s)
    zis = zipFile.get_input_stream(entryName)
    assert_entry_contents_for_stream(filename, zis, entryName)
  ensure
    zis.close if zis
  end
end

module CrcTest
  class TestOutputStream
    include ::Zip::IOExtras::AbstractOutputStream

    attr_accessor :buffer

    def initialize
      @buffer = ''
    end

    def <<(data)
      @buffer << data
      self
    end
  end

  def run_crc_test(compressorClass)
    str = "Here's a nice little text to compute the crc for! Ho hum, it is nice nice nice nice indeed."
    fakeOut = TestOutputStream.new

    deflater = compressorClass.new(fakeOut)
    deflater << str
    assert_equal(0x919920fc, deflater.crc)
  end
end

module Enumerable
  def compare_enumerables(otherEnumerable)
    otherAsArray = otherEnumerable.to_a
    each_with_index do |element, index|
      return false unless yield(element, otherAsArray[index])
    end
    size == otherAsArray.size
  end
end

module CommonZipFileFixture
  include AssertEntry

  EMPTY_FILENAME = 'emptyZipFile.zip'

  TEST_ZIP = TestZipFile::TEST_ZIP2.clone
  TEST_ZIP.zip_name = 'test/data/generated/5entry_copy.zip'

  def setup
    File.delete(EMPTY_FILENAME) if File.exist?(EMPTY_FILENAME)
    FileUtils.cp(TestZipFile::TEST_ZIP2.zip_name, TEST_ZIP.zip_name)
  end
end

module ExtraAssertions
  def assert_forwarded(anObject, method, retVal, *expectedArgs)
    callArgs = nil
    setCallArgsProc = proc { |args| callArgs = args }
    anObject.instance_eval <<-"end_eval"
      alias #{method}_org #{method}
      def #{method}(*args)
        ObjectSpace._id2ref(#{setCallArgsProc.object_id}).call(args)
        ObjectSpace._id2ref(#{retVal.object_id})
        end
    end_eval

    assert_equal(retVal, yield) # Invoke test
    assert_equal(expectedArgs, callArgs)
  ensure
    anObject.instance_eval "undef #{method}; alias #{method} #{method}_org"
  end
end

module ZipEntryData
  TEST_ZIPFILE = 'someZipFile.zip'
  TEST_COMMENT = 'a comment'
  TEST_COMPRESSED_SIZE = 1234
  TEST_CRC = 325_324
  TEST_EXTRA = 'Some data here'
  TEST_COMPRESSIONMETHOD = ::Zip::Entry::DEFLATED
  TEST_NAME = 'entry name'
  TEST_SIZE = 8432
  TEST_ISDIRECTORY = false
  TEST_TIME = Time.now
end
