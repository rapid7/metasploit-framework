#!/usr/bin/env ruby

$VERBOSE = true

$: << "../lib"

require 'test/unit'
require 'fileutils'
require 'zip/zip'
require 'gentestfiles'

include Zip


class ZipEntryTest < Test::Unit::TestCase
  TEST_ZIPFILE = "someZipFile.zip"
  TEST_COMMENT = "a comment"
  TEST_COMPRESSED_SIZE = 1234
  TEST_CRC = 325324
  TEST_EXTRA = "Some data here"
  TEST_COMPRESSIONMETHOD = ZipEntry::DEFLATED
  TEST_NAME = "entry name"
  TEST_SIZE = 8432
  TEST_ISDIRECTORY = false

  def test_constructorAndGetters
    entry = ZipEntry.new(TEST_ZIPFILE,
       TEST_NAME,
       TEST_COMMENT,
       TEST_EXTRA,
       TEST_COMPRESSED_SIZE,
       TEST_CRC,
       TEST_COMPRESSIONMETHOD,
       TEST_SIZE)

    assert_equal(TEST_COMMENT, entry.comment)
    assert_equal(TEST_COMPRESSED_SIZE, entry.compressed_size)
    assert_equal(TEST_CRC, entry.crc)
    assert_instance_of(Zip::ZipExtraField, entry.extra)
    assert_equal(TEST_COMPRESSIONMETHOD, entry.compression_method)
    assert_equal(TEST_NAME, entry.name)
    assert_equal(TEST_SIZE, entry.size)
    assert_equal(TEST_ISDIRECTORY, entry.is_directory)
  end

  def test_is_directoryAndIsFile
    assert(ZipEntry.new(TEST_ZIPFILE, "hello").file?)
    assert(! ZipEntry.new(TEST_ZIPFILE, "hello").directory?)

    assert(ZipEntry.new(TEST_ZIPFILE, "dir/hello").file?)
    assert(! ZipEntry.new(TEST_ZIPFILE, "dir/hello").directory?)

    assert(ZipEntry.new(TEST_ZIPFILE, "hello/").directory?)
    assert(! ZipEntry.new(TEST_ZIPFILE, "hello/").file?)

    assert(ZipEntry.new(TEST_ZIPFILE, "dir/hello/").directory?)
    assert(! ZipEntry.new(TEST_ZIPFILE, "dir/hello/").file?)
  end

  def test_equality
    entry1 = ZipEntry.new("file.zip", "name",  "isNotCompared", 
        "something extra", 123, 1234, 
        ZipEntry::DEFLATED, 10000)  
    entry2 = ZipEntry.new("file.zip", "name",  "isNotComparedXXX", 
        "something extra", 123, 1234, 
        ZipEntry::DEFLATED, 10000)  
    entry3 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extra", 123, 1234, 
        ZipEntry::DEFLATED, 10000)  
    entry4 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extraXX", 123, 1234, 
        ZipEntry::DEFLATED, 10000)  
    entry5 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extraXX", 12,  1234, 
        ZipEntry::DEFLATED, 10000)  
    entry6 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extraXX", 12,  123, 
        ZipEntry::DEFLATED, 10000)  
    entry7 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extraXX", 12,  123,  
        ZipEntry::STORED,   10000)  
    entry8 = ZipEntry.new("file.zip", "name2", "isNotComparedXXX", 
        "something extraXX", 12,  123,  
        ZipEntry::STORED,   100000)  

    assert_equal(entry1, entry1)
    assert_equal(entry1, entry2)

    assert(entry2 != entry3)
    assert(entry3 != entry4)
    assert(entry4 != entry5)
    assert(entry5 != entry6)
    assert(entry6 != entry7)
    assert(entry7 != entry8)

    assert(entry7 != "hello")
    assert(entry7 != 12)
  end

  def test_compare
    assert_equal(0,  (ZipEntry.new("zf.zip", "a") <=> ZipEntry.new("zf.zip", "a")))
    assert_equal(1, (ZipEntry.new("zf.zip", "b") <=> ZipEntry.new("zf.zip", "a")))
    assert_equal(-1,  (ZipEntry.new("zf.zip", "a") <=> ZipEntry.new("zf.zip", "b")))

    entries = [ 
      ZipEntry.new("zf.zip", "5"),
      ZipEntry.new("zf.zip", "1"),
      ZipEntry.new("zf.zip", "3"),
      ZipEntry.new("zf.zip", "4"),
      ZipEntry.new("zf.zip", "0"),
      ZipEntry.new("zf.zip", "2")
    ]

    entries.sort!
    assert_equal("0", entries[0].to_s)
    assert_equal("1", entries[1].to_s)
    assert_equal("2", entries[2].to_s)
    assert_equal("3", entries[3].to_s)
    assert_equal("4", entries[4].to_s)
    assert_equal("5", entries[5].to_s)
  end

  def test_parentAsString
    entry1 = ZipEntry.new("zf.zip", "aa")
    entry2 = ZipEntry.new("zf.zip", "aa/")
    entry3 = ZipEntry.new("zf.zip", "aa/bb")
    entry4 = ZipEntry.new("zf.zip", "aa/bb/")
    entry5 = ZipEntry.new("zf.zip", "aa/bb/cc")
    entry6 = ZipEntry.new("zf.zip", "aa/bb/cc/")

    assert_equal(nil, entry1.parent_as_string)
    assert_equal(nil, entry2.parent_as_string)
    assert_equal("aa/", entry3.parent_as_string)
    assert_equal("aa/", entry4.parent_as_string)
    assert_equal("aa/bb/", entry5.parent_as_string)
    assert_equal("aa/bb/", entry6.parent_as_string)
  end

  def test_entry_name_cannot_start_with_slash
    assert_raise(ZipEntryNameError) { ZipEntry.new("zf.zip", "/hej/der") }
  end
end

module IOizeString
  attr_reader :tell
  
  def read(count = nil)
    @tell ||= 0
    count = size unless count
    retVal = slice(@tell, count)
    @tell += count
    return retVal
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
      raise "Error in test method IOizeString::seek"
    end
    if (newPos < 0 || newPos >= size)
      raise Errno::EINVAL
    else
      @tell=newPos
    end
  end

  def reset
    @tell = 0
  end
end

class ZipLocalEntryTest < Test::Unit::TestCase
  def test_read_local_entryHeaderOfFirstTestZipEntry
    File.open(TestZipFile::TEST_ZIP3.zip_name, "rb") {
      |file|
      entry = ZipEntry.read_local_entry(file)
      
      assert_equal("", entry.comment)
      # Differs from windows and unix because of CR LF
      # assert_equal(480, entry.compressed_size)
      # assert_equal(0x2a27930f, entry.crc)
      # extra field is 21 bytes long
      # probably contains some unix attrutes or something
      # disabled: assert_equal(nil, entry.extra)
      assert_equal(ZipEntry::DEFLATED, entry.compression_method)
      assert_equal(TestZipFile::TEST_ZIP3.entry_names[0], entry.name)
      assert_equal(File.size(TestZipFile::TEST_ZIP3.entry_names[0]), entry.size)
      assert(! entry.is_directory)
    }
  end

  def test_readDateTime
    File.open("data/rubycode.zip", "rb") {
      |file|
      entry = ZipEntry.read_local_entry(file)
      assert_equal("zippedruby1.rb", entry.name)
      assert_equal(Time.at(1019261638), entry.time)
    }
  end

  def test_read_local_entryFromNonZipFile
    File.open("data/file2.txt") {
      |file|
      assert_equal(nil, ZipEntry.read_local_entry(file))
    }
  end

  def test_read_local_entryFromTruncatedZipFile
    zipFragment=""
    File.open(TestZipFile::TEST_ZIP2.zip_name) { |f| zipFragment = f.read(12) } # local header is at least 30 bytes
    zipFragment.extend(IOizeString).reset
    entry = ZipEntry.new
    entry.read_local_entry(zipFragment)
    fail "ZipError expected"
  rescue ZipError
  end

  def test_writeEntry
    entry = ZipEntry.new("file.zip", "entryName", "my little comment", 
       "thisIsSomeExtraInformation", 100, 987654, 
       ZipEntry::DEFLATED, 400)
    write_to_file("localEntryHeader.bin", "centralEntryHeader.bin",  entry)
    entryReadLocal, entryReadCentral = read_from_file("localEntryHeader.bin", "centralEntryHeader.bin")
    compare_local_entry_headers(entry, entryReadLocal)
    compare_c_dir_entry_headers(entry, entryReadCentral)
  end
  
  private
  def compare_local_entry_headers(entry1, entry2)
    assert_equal(entry1.compressed_size   , entry2.compressed_size)
    assert_equal(entry1.crc              , entry2.crc)
    assert_equal(entry1.extra            , entry2.extra)
    assert_equal(entry1.compression_method, entry2.compression_method)
    assert_equal(entry1.name             , entry2.name)
    assert_equal(entry1.size             , entry2.size)
    assert_equal(entry1.localHeaderOffset, entry2.localHeaderOffset)
  end

  def compare_c_dir_entry_headers(entry1, entry2)
    compare_local_entry_headers(entry1, entry2)
    assert_equal(entry1.comment, entry2.comment)
  end

  def write_to_file(localFileName, centralFileName, entry)
    File.open(localFileName,   "wb") { |f| entry.write_local_entry(f) }
    File.open(centralFileName, "wb") { |f| entry.write_c_dir_entry(f)  }
  end

  def read_from_file(localFileName, centralFileName)
    localEntry = nil
    cdirEntry  = nil
    File.open(localFileName,   "rb") { |f| localEntry = ZipEntry.read_local_entry(f) }
    File.open(centralFileName, "rb") { |f| cdirEntry  = ZipEntry.read_c_dir_entry(f) }
    return [localEntry, cdirEntry]
  end
end


module DecompressorTests
  # expects @refText, @refLines and @decompressor

  TEST_FILE="data/file1.txt"

  def setup
    @refText=""
    File.open(TEST_FILE) { |f| @refText = f.read }
    @refLines = @refText.split($/)
  end

  def test_readEverything
    assert_equal(@refText, @decompressor.sysread)
  end
    
  def test_readInChunks
    chunkSize = 5
    while (decompressedChunk = @decompressor.sysread(chunkSize))
      assert_equal(@refText.slice!(0, chunkSize), decompressedChunk)
    end
    assert_equal(0, @refText.size)
  end

  def test_mixingReadsAndProduceInput
    # Just some preconditions to make sure we have enough data for this test
    assert(@refText.length > 1000)
    assert(@refLines.length > 40)

    
    assert_equal(@refText[0...100], @decompressor.sysread(100))

    assert(! @decompressor.input_finished?)
    buf = @decompressor.produce_input
    assert_equal(@refText[100...(100+buf.length)], buf)
  end
end

class InflaterTest < Test::Unit::TestCase
  include DecompressorTests

  def setup
    super
    @file = File.new("data/file1.txt.deflatedData", "rb")
    @decompressor = Inflater.new(@file)
  end

  def teardown
    @file.close
  end
end


class PassThruDecompressorTest < Test::Unit::TestCase
  include DecompressorTests
  def setup
    super
    @file = File.new(TEST_FILE)
    @decompressor = PassThruDecompressor.new(@file, File.size(TEST_FILE))
  end

  def teardown
    @file.close
  end
end

 
module AssertEntry
  def assert_next_entry(filename, zis)
    assert_entry(filename, zis, zis.get_next_entry.name)
  end

  def assert_entry(filename, zis, entryName)
    assert_equal(filename, entryName)
    assert_entryContentsForStream(filename, zis, entryName)
  end

  def assert_entryContentsForStream(filename, zis, entryName)
    File.open(filename, "rb") {
      |file|
      expected = file.read
      actual   = zis.read
      if (expected != actual)
  if ((expected && actual) && (expected.length > 400 || actual.length > 400))
    zipEntryFilename=entryName+".zipEntry"
    File.open(zipEntryFilename, "wb") { |f| f << actual }
    fail("File '#{filename}' is different from '#{zipEntryFilename}'")
  else
    assert_equal(expected, actual)
  end
      end
    }
  end

  def AssertEntry.assert_contents(filename, aString)
    fileContents = ""
    File.open(filename, "rb") { |f| fileContents = f.read }
    if (fileContents != aString)
      if (fileContents.length > 400 || aString.length > 400)
  stringFile = filename + ".other"
  File.open(stringFile, "wb") { |f| f << aString }
  fail("File '#{filename}' is different from contents of string stored in '#{stringFile}'")
      else
  assert_equal(fileContents, aString)
      end
    end
  end

  def assert_stream_contents(zis, testZipFile)
    assert(zis != nil)
    testZipFile.entry_names.each {
      |entryName|
      assert_next_entry(entryName, zis)
    }
    assert_equal(nil, zis.get_next_entry)
  end

  def assert_test_zip_contents(testZipFile)
    ZipInputStream.open(testZipFile.zip_name) {
      |zis|
      assert_stream_contents(zis, testZipFile)
    }
  end

  def assert_entryContents(zipFile, entryName, filename = entryName.to_s)
    zis = zipFile.get_input_stream(entryName)
    assert_entryContentsForStream(filename, zis, entryName)
  ensure 
    zis.close if zis
  end
end



class ZipInputStreamTest < Test::Unit::TestCase
  include AssertEntry

  def test_new
    zis = ZipInputStream.new(TestZipFile::TEST_ZIP2.zip_name)
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
    assert_equal(true, zis.eof?)
    zis.close    
  end

  def test_openWithBlock
    ZipInputStream.open(TestZipFile::TEST_ZIP2.zip_name) {
      |zis|
      assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
      assert_equal(true, zis.eof?)
    }
  end

  def test_openWithoutBlock
    zis = ZipInputStream.open(TestZipFile::TEST_ZIP2.zip_name)
    assert_stream_contents(zis, TestZipFile::TEST_ZIP2)
  end

  def test_incompleteReads
    ZipInputStream.open(TestZipFile::TEST_ZIP2.zip_name) {
      |zis|
      entry = zis.get_next_entry # longAscii.txt
      assert_equal(false, zis.eof?)
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[0], entry.name)
      assert zis.gets.length > 0
      assert_equal(false, zis.eof?)
      entry = zis.get_next_entry # empty.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[1], entry.name)
      assert_equal(0, entry.size)
      assert_equal(nil, zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # empty_chmod640.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[2], entry.name)
      assert_equal(0, entry.size)
      assert_equal(nil, zis.gets)
      assert_equal(true, zis.eof?)
      entry = zis.get_next_entry # short.txt
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[3], entry.name)
      assert zis.gets.length > 0
      entry = zis.get_next_entry # longBinary.bin
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[4], entry.name)
      assert zis.gets.length > 0
    }
  end

  def test_rewind
    ZipInputStream.open(TestZipFile::TEST_ZIP2.zip_name) {
      |zis|
      e = zis.get_next_entry
      assert_equal(TestZipFile::TEST_ZIP2.entry_names[0], e.name)

      # Do a little reading
      buf = ""
      buf << zis.read(100)
      buf << (zis.gets || "")
      buf << (zis.gets || "")
      assert_equal(false, zis.eof?)

      zis.rewind

      buf2 = ""
      buf2 << zis.read(100)
      buf2 << (zis.gets || "")
      buf2 << (zis.gets || "")

      assert_equal(buf, buf2)

      zis.rewind
      assert_equal(false, zis.eof?)

      assert_entry(e.name, zis, e.name)
    }
  end

  def test_mix_read_and_gets
    ZipInputStream.open(TestZipFile::TEST_ZIP2.zip_name) {
      |zis|
      e = zis.get_next_entry
      assert_equal("#!/usr/bin/env ruby", zis.gets.chomp)
      assert_equal(false, zis.eof?)
      assert_equal("", zis.gets.chomp)
      assert_equal(false, zis.eof?)
      assert_equal("$VERBOSE =", zis.read(10))
      assert_equal(false, zis.eof?)
    }
  end
  
end


module CrcTest

  class TestOutputStream
    include IOExtras::AbstractOutputStream

    attr_accessor :buffer

    def initialize
      @buffer = ""
    end

    def << (data)
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



class PassThruCompressorTest < Test::Unit::TestCase
  include CrcTest

  def test_size
    File.open("dummy.txt", "wb") {
      |file|
      compressor = PassThruCompressor.new(file)
      
      assert_equal(0, compressor.size)
      
      t1 = "hello world"
      t2 = ""
      t3 = "bingo"
      
      compressor << t1
      assert_equal(compressor.size, t1.size)
      
      compressor << t2
      assert_equal(compressor.size, t1.size + t2.size)
      
      compressor << t3
      assert_equal(compressor.size, t1.size + t2.size + t3.size)
    }
  end

  def test_crc
    run_crc_test(PassThruCompressor)
  end
end

class DeflaterTest < Test::Unit::TestCase
  include CrcTest

  def test_outputOperator
    txt = load_file("data/file2.txt")
    deflate(txt, "deflatertest.bin")
    inflatedTxt = inflate("deflatertest.bin")
    assert_equal(txt, inflatedTxt)
  end

  private
  def load_file(fileName)
    txt = nil
    File.open(fileName, "rb") { |f| txt = f.read }
  end

  def deflate(data, fileName)
    File.open(fileName, "wb") {
      |file|
      deflater = Deflater.new(file)
      deflater << data
      deflater.finish
      assert_equal(deflater.size, data.size)
      file << "trailing data for zlib with -MAX_WBITS"
    }
  end

  def inflate(fileName)
    txt = nil
    File.open(fileName, "rb") {
      |file|
      inflater = Inflater.new(file)
      txt = inflater.sysread
    }
  end

  def test_crc
    run_crc_test(Deflater)
  end
end

class ZipOutputStreamTest < Test::Unit::TestCase
  include AssertEntry

  TEST_ZIP = TestZipFile::TEST_ZIP2.clone
  TEST_ZIP.zip_name = "output.zip"

  def test_new
    zos = ZipOutputStream.new(TEST_ZIP.zip_name)
    zos.comment = TEST_ZIP.comment
    write_test_zip(zos)
    zos.close
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_open
    ZipOutputStream.open(TEST_ZIP.zip_name) {
      |zos|
      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    }
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_writingToClosedStream
    assert_i_o_error_in_closed_stream { |zos| zos << "hello world" }
    assert_i_o_error_in_closed_stream { |zos| zos.puts "hello world" }
    assert_i_o_error_in_closed_stream { |zos| zos.write "hello world" }
  end

  def test_cannotOpenFile
    name = TestFiles::EMPTY_TEST_DIR
    begin
      zos = ZipOutputStream.open(name)
    rescue Exception
      assert($!.kind_of?(Errno::EISDIR) || # Linux 
       $!.kind_of?(Errno::EEXIST) || # Windows/cygwin
       $!.kind_of?(Errno::EACCES),   # Windows
        "Expected Errno::EISDIR (or on win/cygwin: Errno::EEXIST), but was: #{$!.class}")
    end
  end

  def test_put_next_entry
    stored_text = "hello world in stored text"
    entry_name = "file1"
    comment = "my comment"
    ZipOutputStream.open(TEST_ZIP.zip_name) do
      |zos|
      zos.put_next_entry(entry_name, comment, nil, ZipEntry::STORED)
      zos << stored_text
    end

  fdata = File.read(TEST_ZIP.zip_name)
  if fdata.respond_to? :force_encoding
    fdata.force_encoding("binary")
  end
    assert(fdata.split("\n").grep(stored_text))
    ZipFile.open(TEST_ZIP.zip_name) do
      |zf|
      assert_equal(stored_text, zf.read(entry_name))
    end
  end

  def assert_i_o_error_in_closed_stream
    assert_raise(IOError) {
      zos = ZipOutputStream.new("test_putOnClosedStream.zip")
      zos.close
      yield zos
    }
  end

  def write_test_zip(zos)
    TEST_ZIP.entry_names.each {
      |entryName|
      zos.put_next_entry(entryName)
      File.open(entryName, "rb") { |f| zos.write(f.read) }
    }
  end
end



module Enumerable
  def compare_enumerables(otherEnumerable)
    otherAsArray = otherEnumerable.to_a
    index=0
    each_with_index {
      |element, i|
      return false unless yield(element, otherAsArray[i])
    }
    return index+1 == otherAsArray.size
  end
end


class ZipCentralDirectoryEntryTest < Test::Unit::TestCase

  def test_read_from_stream
    File.open("data/testDirectory.bin", "rb") {
      |file|
      entry = ZipEntry.read_c_dir_entry(file)
      
      assert_equal("longAscii.txt", entry.name)
      assert_equal(ZipEntry::DEFLATED, entry.compression_method)
      assert_equal(106490, entry.size)
      assert_equal(3784, entry.compressed_size)
      assert_equal(0xfcd1799c, entry.crc)
      assert_equal("", entry.comment)

      entry = ZipEntry.read_c_dir_entry(file)
      assert_equal("empty.txt", entry.name)
      assert_equal(ZipEntry::STORED, entry.compression_method)
      assert_equal(0, entry.size)
      assert_equal(0, entry.compressed_size)
      assert_equal(0x0, entry.crc)
      assert_equal("", entry.comment)

      entry = ZipEntry.read_c_dir_entry(file)
      assert_equal("short.txt", entry.name)
      assert_equal(ZipEntry::STORED, entry.compression_method)
      assert_equal(6, entry.size)
      assert_equal(6, entry.compressed_size)
      assert_equal(0xbb76fe69, entry.crc)
      assert_equal("", entry.comment)

      entry = ZipEntry.read_c_dir_entry(file)
      assert_equal("longBinary.bin", entry.name)
      assert_equal(ZipEntry::DEFLATED, entry.compression_method)
      assert_equal(1000024, entry.size)
      assert_equal(70847, entry.compressed_size)
      assert_equal(0x10da7d59, entry.crc)
      assert_equal("", entry.comment)

      entry = ZipEntry.read_c_dir_entry(file)
      assert_equal(nil, entry)
# Fields that are not check by this test:
#          version made by                 2 bytes
#          version needed to extract       2 bytes
#          general purpose bit flag        2 bytes
#          last mod file time              2 bytes
#          last mod file date              2 bytes
#          compressed size                 4 bytes
#          uncompressed size               4 bytes
#          disk number start               2 bytes
#          internal file attributes        2 bytes
#          external file attributes        4 bytes
#          relative offset of local header 4 bytes

#          file name (variable size)
#          extra field (variable size)
#          file comment (variable size)

    }
  end

  def test_ReadEntryFromTruncatedZipFile
    fragment=""
    File.open("data/testDirectory.bin") { |f| fragment = f.read(12) } # cdir entry header is at least 46 bytes
    fragment.extend(IOizeString)
    entry = ZipEntry.new
    entry.read_c_dir_entry(fragment)
    fail "ZipError expected"
  rescue ZipError
  end

end


class ZipEntrySetTest < Test::Unit::TestCase
  ZIP_ENTRIES = [ 
    ZipEntry.new("zipfile.zip", "name1", "comment1"),
    ZipEntry.new("zipfile.zip", "name2", "comment1"),
    ZipEntry.new("zipfile.zip", "name3", "comment1"),
    ZipEntry.new("zipfile.zip", "name4", "comment1"),
    ZipEntry.new("zipfile.zip", "name5", "comment1"),
    ZipEntry.new("zipfile.zip", "name6", "comment1")
  ]

  def setup
    @zipEntrySet = ZipEntrySet.new(ZIP_ENTRIES)
  end

  def test_include
    assert(@zipEntrySet.include?(ZIP_ENTRIES.first))
    assert(! @zipEntrySet.include?(ZipEntry.new("different.zip", "different", "aComment")))
  end

  def test_size
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.length)
    @zipEntrySet << ZipEntry.new("a", "b", "c")
    assert_equal(ZIP_ENTRIES.size + 1, @zipEntrySet.length)
  end

  def test_add
    zes = ZipEntrySet.new
    entry1 = ZipEntry.new("zf.zip", "name1")
    entry2 = ZipEntry.new("zf.zip", "name2")
    zes << entry1
    assert(zes.include?(entry1))
    zes.push(entry2)
    assert(zes.include?(entry2))
  end

  def test_delete
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    entry = @zipEntrySet.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zipEntrySet.size)
    assert_equal(ZIP_ENTRIES.first, entry)

    entry = @zipEntrySet.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zipEntrySet.size)
    assert_nil(entry)
  end

  def test_each
    # Tested indirectly via each_with_index
    count = 0
    @zipEntrySet.each_with_index { 
      |entry, index|
      assert(ZIP_ENTRIES.include?(entry))
      count = count.succ
    }
    assert_equal(ZIP_ENTRIES.size, count)
  end

  def test_entries
    assert_equal(ZIP_ENTRIES.sort, @zipEntrySet.entries.sort)
  end

  def test_compound
    newEntry = ZipEntry.new("zf.zip", "new entry", "new entry's comment")
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
    @zipEntrySet << newEntry
    assert_equal(ZIP_ENTRIES.size + 1, @zipEntrySet.size)
    assert(@zipEntrySet.include?(newEntry))

    @zipEntrySet.delete(newEntry)
    assert_equal(ZIP_ENTRIES.size, @zipEntrySet.size)
  end

  def test_dup
    copy = @zipEntrySet.dup
    assert_equal(@zipEntrySet, copy)

    # demonstrate that this is a deep copy
    copy.entries[0].name = "a totally different name"
    assert(@zipEntrySet != copy)
  end

  def test_parent
    entries = [ 
      ZipEntry.new("zf.zip", "a"),
      ZipEntry.new("zf.zip", "a/"),
      ZipEntry.new("zf.zip", "a/b"),
      ZipEntry.new("zf.zip", "a/b/"),
      ZipEntry.new("zf.zip", "a/b/c"),
      ZipEntry.new("zf.zip", "a/b/c/")
    ]
    entrySet = ZipEntrySet.new(entries)
    
    assert_equal(nil, entrySet.parent(entries[0]))
    assert_equal(nil, entrySet.parent(entries[1]))
    assert_equal(entries[1], entrySet.parent(entries[2]))
    assert_equal(entries[1], entrySet.parent(entries[3]))
    assert_equal(entries[3], entrySet.parent(entries[4]))
    assert_equal(entries[3], entrySet.parent(entries[5]))
  end

  def test_glob
    res = @zipEntrySet.glob('name[2-4]')
    assert_equal(3, res.size)
    assert_equal(ZIP_ENTRIES[1,3], res)
  end

  def test_glob2
    entries = [ 
      ZipEntry.new("zf.zip", "a/"),
      ZipEntry.new("zf.zip", "a/b/b1"),
      ZipEntry.new("zf.zip", "a/b/c/"),
      ZipEntry.new("zf.zip", "a/b/c/c1")
    ]
    entrySet = ZipEntrySet.new(entries)

    assert_equal(entries[0,1], entrySet.glob("*"))
#    assert_equal(entries[FIXME], entrySet.glob("**"))
#    res = entrySet.glob('a*')
#    assert_equal(entries.size, res.size)
#    assert_equal(entrySet.map { |e| e.name }, res.map { |e| e.name })
  end
end


class ZipCentralDirectoryTest < Test::Unit::TestCase

  def test_read_from_stream
    File.open(TestZipFile::TEST_ZIP2.zip_name, "rb") {
      |zipFile|
      cdir = ZipCentralDirectory.read_from_stream(zipFile)
      assert_equal(TestZipFile::TEST_ZIP2.entry_names.size, cdir.size)
      cdir.entries.sort.compare_enumerables(TestZipFile::TEST_ZIP2.entry_names.sort) { 
          |cdirEntry, testEntryName|
          assert(cdirEntry.name == testEntryName)
        }
      assert_equal(TestZipFile::TEST_ZIP2.comment, cdir.comment)
    }
  end

  def test_readFromInvalidStream
    File.open("data/file2.txt", "rb") {
      |zipFile|
      cdir = ZipCentralDirectory.new
      cdir.read_from_stream(zipFile)
    }
    fail "ZipError expected!"
  rescue ZipError
  end

  def test_ReadFromTruncatedZipFile
    fragment=""
    File.open("data/testDirectory.bin") { |f| fragment = f.read }
    fragment.slice!(12) # removed part of first cdir entry. eocd structure still complete
    fragment.extend(IOizeString)
    entry = ZipCentralDirectory.new
    entry.read_from_stream(fragment)
    fail "ZipError expected"
  rescue ZipError
  end

  def test_write_to_stream
    entries = [ ZipEntry.new("file.zip", "flimse", "myComment", "somethingExtra"),
      ZipEntry.new("file.zip", "secondEntryName"),
      ZipEntry.new("file.zip", "lastEntry.txt", "Has a comment too") ]
    cdir = ZipCentralDirectory.new(entries, "my zip comment")
    File.open("cdirtest.bin", "wb") { |f| cdir.write_to_stream(f) }
    cdirReadback = ZipCentralDirectory.new
    File.open("cdirtest.bin", "rb") { |f| cdirReadback.read_from_stream(f) }
    
    assert_equal(cdir.entries.sort, cdirReadback.entries.sort)
  end

  def test_equality
    cdir1 = ZipCentralDirectory.new([ ZipEntry.new("file.zip", "flimse", nil, 
               "somethingExtra"),
             ZipEntry.new("file.zip", "secondEntryName"),
             ZipEntry.new("file.zip", "lastEntry.txt") ], 
           "my zip comment")
    cdir2 = ZipCentralDirectory.new([ ZipEntry.new("file.zip", "flimse", nil, 
               "somethingExtra"),
             ZipEntry.new("file.zip", "secondEntryName"),
             ZipEntry.new("file.zip", "lastEntry.txt") ], 
           "my zip comment")
    cdir3 = ZipCentralDirectory.new([ ZipEntry.new("file.zip", "flimse", nil, 
               "somethingExtra"),
             ZipEntry.new("file.zip", "secondEntryName"),
             ZipEntry.new("file.zip", "lastEntry.txt") ], 
           "comment?")
    cdir4 = ZipCentralDirectory.new([ ZipEntry.new("file.zip", "flimse", nil, 
               "somethingExtra"),
             ZipEntry.new("file.zip", "lastEntry.txt") ], 
           "comment?")
    assert_equal(cdir1, cdir1)
    assert_equal(cdir1, cdir2)

    assert(cdir1 !=  cdir3)
    assert(cdir2 !=  cdir3)
    assert(cdir2 !=  cdir3)
    assert(cdir3 !=  cdir4)

    assert(cdir3 !=  "hello")
  end
end


class BasicZipFileTest < Test::Unit::TestCase
  include AssertEntry

  def setup
    @zipFile = ZipFile.new(TestZipFile::TEST_ZIP2.zip_name)
    @testEntryNameIndex=0
  end

  def test_entries
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.sort, 
      @zipFile.entries.entries.sort.map {|e| e.name} )
  end

  def test_each
    count = 0
    visited = {}
    @zipFile.each {
      |entry|
      assert(TestZipFile::TEST_ZIP2.entry_names.include?(entry.name))
      assert(! visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    }
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_foreach
    count = 0
    visited = {}
    ZipFile.foreach(TestZipFile::TEST_ZIP2.zip_name) {
      |entry|
      assert(TestZipFile::TEST_ZIP2.entry_names.include?(entry.name))
      assert(! visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    }
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_get_input_stream
    count = 0
    visited = {}
    @zipFile.each {
      |entry|
      assert_entry(entry.name, @zipFile.get_input_stream(entry), entry.name)
      assert(! visited.include?(entry.name))
      visited[entry.name] = nil
      count = count.succ
    }
    assert_equal(TestZipFile::TEST_ZIP2.entry_names.length, count)
  end

  def test_get_input_streamBlock
    fileAndEntryName = @zipFile.entries.first.name
    @zipFile.get_input_stream(fileAndEntryName) {
      |zis|
      assert_entryContentsForStream(fileAndEntryName, 
           zis, 
           fileAndEntryName)
    }
  end
end

module CommonZipFileFixture 
  include AssertEntry

  EMPTY_FILENAME = "emptyZipFile.zip"

  TEST_ZIP = TestZipFile::TEST_ZIP2.clone
  TEST_ZIP.zip_name = "5entry_copy.zip"

  def setup
    File.delete(EMPTY_FILENAME) if File.exists?(EMPTY_FILENAME)
    FileUtils.cp(TestZipFile::TEST_ZIP2.zip_name, TEST_ZIP.zip_name)
  end
end

class ZipFileTest < Test::Unit::TestCase
  include CommonZipFileFixture

  def test_createFromScratch
    comment  = "a short comment"

    zf = ZipFile.new(EMPTY_FILENAME, ZipFile::CREATE)
    zf.get_output_stream("myFile") { |os| os.write "myFile contains just this" }
    zf.mkdir("dir1")
    zf.comment = comment
    zf.close

    zfRead = ZipFile.new(EMPTY_FILENAME)
    assert_equal(comment, zfRead.comment)
    assert_equal(2, zfRead.entries.length)
  end

  def test_get_output_stream
    entryCount = nil
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      entryCount = zf.size
      zf.get_output_stream('newEntry.txt') {
        |os|
        os.write "Putting stuff in newEntry.txt"
      }
      assert_equal(entryCount+1, zf.size)
      assert_equal("Putting stuff in newEntry.txt", zf.read("newEntry.txt")) 

      zf.get_output_stream(zf.get_entry('data/generated/empty.txt')) {
        |os|
        os.write "Putting stuff in data/generated/empty.txt"
      }
      assert_equal(entryCount+1, zf.size)
      assert_equal("Putting stuff in data/generated/empty.txt", zf.read("data/generated/empty.txt")) 

      zf.get_output_stream('entry.bin') {
  |os|
  os.write(File.open('data/generated/5entry.zip', 'rb').read)
      }
    }
    
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      assert_equal(entryCount+2, zf.size)
      assert_equal("Putting stuff in newEntry.txt", zf.read("newEntry.txt")) 
      assert_equal("Putting stuff in data/generated/empty.txt", zf.read("data/generated/empty.txt")) 
      assert_equal(File.open('data/generated/5entry.zip', 'rb').read, zf.read("entry.bin")) 
    }
  end

  def test_add
    srcFile   = "data/file2.txt"
    entryName = "newEntryName.rb" 
    assert(File.exists?(srcFile))
    zf = ZipFile.new(EMPTY_FILENAME, ZipFile::CREATE)
    zf.add(entryName, srcFile)
    zf.close

    zfRead = ZipFile.new(EMPTY_FILENAME)
    assert_equal("", zfRead.comment)
    assert_equal(1, zfRead.entries.length)
    assert_equal(entryName, zfRead.entries.first.name)
    AssertEntry.assert_contents(srcFile, 
             zfRead.get_input_stream(entryName) { |zis| zis.read })
  end

  def test_addExistingEntryName
    assert_raise(ZipEntryExistsError) {
      ZipFile.open(TEST_ZIP.zip_name) {
  |zf|
  zf.add(zf.entries.first.name, "data/file2.txt")
      }
    }
  end

  def test_addExistingEntryNameReplace
    gotCalled = false
    replacedEntry = nil
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      replacedEntry = zf.entries.first.name
      zf.add(replacedEntry, "data/file2.txt") { gotCalled = true; true }
    }
    assert(gotCalled)
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      assert_contains(zf, replacedEntry, "data/file2.txt")
    }
  end

  def test_addDirectory
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      zf.add(TestFiles::EMPTY_TEST_DIR, TestFiles::EMPTY_TEST_DIR)
    }
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      dirEntry = zf.entries.detect { |e| e.name == TestFiles::EMPTY_TEST_DIR+"/" } 
      assert(dirEntry.is_directory)
    }
  end

  def test_remove
    entryToRemove, *remainingEntries = TEST_ZIP.entry_names

    FileUtils.cp(TestZipFile::TEST_ZIP2.zip_name, TEST_ZIP.zip_name)

    zf = ZipFile.new(TEST_ZIP.zip_name)
    assert(zf.entries.map { |e| e.name }.include?(entryToRemove))
    zf.remove(entryToRemove)
    assert(! zf.entries.map { |e| e.name }.include?(entryToRemove))
    assert_equal(zf.entries.map {|x| x.name }.sort, remainingEntries.sort) 
    zf.close

    zfRead = ZipFile.new(TEST_ZIP.zip_name)
    assert(! zfRead.entries.map { |e| e.name }.include?(entryToRemove))
    assert_equal(zfRead.entries.map {|x| x.name }.sort, remainingEntries.sort) 
    zfRead.close
  end

  def test_rename
    entryToRename, *remainingEntries = TEST_ZIP.entry_names

    zf = ZipFile.new(TEST_ZIP.zip_name)
    assert(zf.entries.map { |e| e.name }.include?(entryToRename))

    contents = zf.read(entryToRename)
    newName = "changed entry name"
    assert(! zf.entries.map { |e| e.name }.include?(newName))

    zf.rename(entryToRename, newName)
    assert(zf.entries.map { |e| e.name }.include?(newName))

    assert_equal(contents, zf.read(newName))

    zf.close

    zfRead = ZipFile.new(TEST_ZIP.zip_name)
    assert(zfRead.entries.map { |e| e.name }.include?(newName))
    assert_equal(contents, zf.read(newName))
    zfRead.close    
  end

  def test_renameToExistingEntry
    oldEntries = nil
    ZipFile.open(TEST_ZIP.zip_name) { |zf| oldEntries = zf.entries }

    assert_raise(ZipEntryExistsError) {
      ZipFile.open(TEST_ZIP.zip_name) {
  |zf|
  zf.rename(zf.entries[0], zf.entries[1].name)
      }
    }

    ZipFile.open(TEST_ZIP.zip_name) { 
      |zf| 
      assert_equal(oldEntries.sort.map{ |e| e.name }, zf.entries.sort.map{ |e| e.name })
    }
  end

  def test_renameToExistingEntryOverwrite
    oldEntries = nil
    ZipFile.open(TEST_ZIP.zip_name) { |zf| oldEntries = zf.entries }
    
    gotCalled = false
    renamedEntryName = nil
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      renamedEntryName = zf.entries[0].name
      zf.rename(zf.entries[0], zf.entries[1].name) { gotCalled = true; true }
    }

    assert(gotCalled)
    oldEntries.delete_if { |e| e.name == renamedEntryName }
    ZipFile.open(TEST_ZIP.zip_name) { 
      |zf| 
      assert_equal(oldEntries.sort.map{ |e| e.name }, 
        zf.entries.sort.map{ |e| e.name })
    }
  end

  def test_renameNonEntry
    nonEntry = "bogusEntry"
    target_entry = "target_entryName"
    zf = ZipFile.new(TEST_ZIP.zip_name)
    assert(! zf.entries.include?(nonEntry))
    assert_raise(Errno::ENOENT) {
      zf.rename(nonEntry, target_entry)
    }
    zf.commit
    assert(! zf.entries.include?(target_entry))
  ensure
    zf.close
  end

  def test_renameEntryToExistingEntry
    entry1, entry2, *remaining = TEST_ZIP.entry_names
    zf = ZipFile.new(TEST_ZIP.zip_name)
    assert_raise(ZipEntryExistsError) {
      zf.rename(entry1, entry2)
    }
  ensure 
    zf.close
  end

  def test_replace
    entryToReplace = TEST_ZIP.entry_names[2]
    newEntrySrcFilename = "data/file2.txt" 
    zf = ZipFile.new(TEST_ZIP.zip_name)
    zf.replace(entryToReplace, newEntrySrcFilename)
    
    zf.close
    zfRead = ZipFile.new(TEST_ZIP.zip_name)
    AssertEntry::assert_contents(newEntrySrcFilename, 
        zfRead.get_input_stream(entryToReplace) { |is| is.read })
    AssertEntry::assert_contents(TEST_ZIP.entry_names[0], 
        zfRead.get_input_stream(TEST_ZIP.entry_names[0]) { |is| is.read })
    AssertEntry::assert_contents(TEST_ZIP.entry_names[1], 
        zfRead.get_input_stream(TEST_ZIP.entry_names[1]) { |is| is.read })
    AssertEntry::assert_contents(TEST_ZIP.entry_names[3], 
        zfRead.get_input_stream(TEST_ZIP.entry_names[3]) { |is| is.read })
    zfRead.close    
  end

  def test_replaceNonEntry
    entryToReplace = "nonExistingEntryname"
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      assert_raise(Errno::ENOENT) {
  zf.replace(entryToReplace, "data/file2.txt")
      }
    }
  end

  def test_commit
    newName = "renamedFirst"
    zf = ZipFile.new(TEST_ZIP.zip_name)
    oldName = zf.entries.first
    zf.rename(oldName, newName)
    zf.commit

    zfRead = ZipFile.new(TEST_ZIP.zip_name)
    assert(zfRead.entries.detect { |e| e.name == newName } != nil)
    assert(zfRead.entries.detect { |e| e.name == oldName } == nil)
    zfRead.close

    zf.close
  end

  # This test tests that after commit, you
  # can delete the file you used to add the entry to the zip file
  # with
  def test_commitUseZipEntry
    FileUtils.cp(TestFiles::RANDOM_ASCII_FILE1, "okToDelete.txt")
    zf = ZipFile.open(TEST_ZIP.zip_name)
    zf.add("okToDelete.txt", "okToDelete.txt")
    assert_contains(zf, "okToDelete.txt")
    zf.commit
    File.rename("okToDelete.txt", "okToDeleteMoved.txt")
    assert_contains(zf, "okToDelete.txt", "okToDeleteMoved.txt")
  end

#  def test_close
#    zf = ZipFile.new(TEST_ZIP.zip_name)
#    zf.close
#    assert_raise(IOError) {
#      zf.extract(TEST_ZIP.entry_names.first, "hullubullu")
#    }
#  end

  def test_compound1
    renamedName = "renamedName"
    originalEntries = []
    begin
      zf = ZipFile.new(TEST_ZIP.zip_name)
      originalEntries = zf.entries.dup

      assert_not_contains(zf, TestFiles::RANDOM_ASCII_FILE1)
      zf.add(TestFiles::RANDOM_ASCII_FILE1, 
       TestFiles::RANDOM_ASCII_FILE1)
      assert_contains(zf, TestFiles::RANDOM_ASCII_FILE1)

      zf.rename(zf.entries[0], renamedName)
      assert_contains(zf, renamedName)

      TestFiles::BINARY_TEST_FILES.each {
  |filename|
  zf.add(filename, filename)
  assert_contains(zf, filename)
      }

      assert_contains(zf, originalEntries.last.to_s)
      zf.remove(originalEntries.last.to_s)
      assert_not_contains(zf, originalEntries.last.to_s)
      
    ensure
      zf.close
    end
    begin
      zfRead = ZipFile.new(TEST_ZIP.zip_name)
      assert_contains(zfRead, TestFiles::RANDOM_ASCII_FILE1)
      assert_contains(zfRead, renamedName)
      TestFiles::BINARY_TEST_FILES.each {
  |filename|
  assert_contains(zfRead, filename)
      }
      assert_not_contains(zfRead, originalEntries.last.to_s)
    ensure
      zfRead.close
    end
  end

  def test_compound2
    begin
      zf = ZipFile.new(TEST_ZIP.zip_name)
      originalEntries = zf.entries.dup
      
      originalEntries.each {
  |entry|
  zf.remove(entry)
  assert_not_contains(zf, entry)
      }
      assert(zf.entries.empty?)
      
      TestFiles::ASCII_TEST_FILES.each {
  |filename|
  zf.add(filename, filename)
  assert_contains(zf, filename)
      }
      assert_equal(zf.entries.sort.map { |e| e.name }, TestFiles::ASCII_TEST_FILES)
      
      zf.rename(TestFiles::ASCII_TEST_FILES[0], "newName")
      assert_not_contains(zf, TestFiles::ASCII_TEST_FILES[0])
      assert_contains(zf, "newName")
    ensure
      zf.close
    end
    begin
      zfRead = ZipFile.new(TEST_ZIP.zip_name)
      asciiTestFiles = TestFiles::ASCII_TEST_FILES.dup
      asciiTestFiles.shift
      asciiTestFiles.each {
  |filename|
  assert_contains(zf, filename)
      }

      assert_contains(zf, "newName")
    ensure
      zfRead.close
    end
  end

  private
  def assert_contains(zf, entryName, filename = entryName)
    assert(zf.entries.detect { |e| e.name == entryName} != nil, "entry #{entryName} not in #{zf.entries.join(', ')} in zip file #{zf}")
    assert_entryContents(zf, entryName, filename) if File.exists?(filename)
  end
  
  def assert_not_contains(zf, entryName)
    assert(zf.entries.detect { |e| e.name == entryName} == nil, "entry #{entryName} in #{zf.entries.join(', ')} in zip file #{zf}")
  end
end

class ZipFileExtractTest < Test::Unit::TestCase
  include CommonZipFileFixture
  EXTRACTED_FILENAME = "extEntry"
  ENTRY_TO_EXTRACT, *REMAINING_ENTRIES = TEST_ZIP.entry_names.reverse

  def setup
    super
    File.delete(EXTRACTED_FILENAME) if File.exists?(EXTRACTED_FILENAME)
  end

  def test_extract
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      zf.extract(ENTRY_TO_EXTRACT, EXTRACTED_FILENAME)
      
      assert(File.exists?(EXTRACTED_FILENAME))
      AssertEntry::assert_contents(EXTRACTED_FILENAME, 
          zf.get_input_stream(ENTRY_TO_EXTRACT) { |is| is.read })


      File::unlink(EXTRACTED_FILENAME)

      entry = zf.get_entry(ENTRY_TO_EXTRACT)
      entry.extract(EXTRACTED_FILENAME)

      assert(File.exists?(EXTRACTED_FILENAME))
      AssertEntry::assert_contents(EXTRACTED_FILENAME, 
          entry.get_input_stream() { |is| is.read })

    }
  end

  def test_extractExists
    writtenText = "written text"
    File.open(EXTRACTED_FILENAME, "w") { |f| f.write(writtenText) }

    assert_raise(ZipDestinationFileExistsError) {
      ZipFile.open(TEST_ZIP.zip_name) { 
  |zf| 
  zf.extract(zf.entries.first, EXTRACTED_FILENAME) 
      }
    }
    File.open(EXTRACTED_FILENAME, "r") {
      |f|
      assert_equal(writtenText, f.read)
    }
  end

  def test_extractExistsOverwrite
    writtenText = "written text"
    File.open(EXTRACTED_FILENAME, "w") { |f| f.write(writtenText) }

    gotCalledCorrectly = false
    ZipFile.open(TEST_ZIP.zip_name) {
      |zf|
      zf.extract(zf.entries.first, EXTRACTED_FILENAME) { 
        |entry, extractLoc| 
        gotCalledCorrectly = zf.entries.first == entry && 
                                    extractLoc == EXTRACTED_FILENAME
        true 
        }
    }

    assert(gotCalledCorrectly)
    File.open(EXTRACTED_FILENAME, "r") {
      |f|
      assert(writtenText != f.read)
    }
  end

  def test_extractNonEntry
    zf = ZipFile.new(TEST_ZIP.zip_name)
    assert_raise(Errno::ENOENT) { zf.extract("nonExistingEntry", "nonExistingEntry") }
  ensure
    zf.close if zf
  end

  def test_extractNonEntry2
    outFile = "outfile"
    assert_raise(Errno::ENOENT) {
      zf = ZipFile.new(TEST_ZIP.zip_name)
      nonEntry = "hotdog-diddelidoo"
      assert(! zf.entries.include?(nonEntry))
      zf.extract(nonEntry, outFile)
      zf.close
    }
    assert(! File.exists?(outFile))
  end

end

class ZipFileExtractDirectoryTest < Test::Unit::TestCase
  include CommonZipFileFixture
  TEST_OUT_NAME = "emptyOutDir"

  def open_zip(&aProc)
    assert(aProc != nil)
    ZipFile.open(TestZipFile::TEST_ZIP4.zip_name, &aProc)
  end

  def extract_test_dir(&aProc)
    open_zip {
      |zf|
      zf.extract(TestFiles::EMPTY_TEST_DIR, TEST_OUT_NAME, &aProc)
    }
  end

  def setup
    super

    Dir.rmdir(TEST_OUT_NAME)   if File.directory? TEST_OUT_NAME
    File.delete(TEST_OUT_NAME) if File.exists?    TEST_OUT_NAME
  end
    
  def test_extractDirectory
    extract_test_dir
    assert(File.directory?(TEST_OUT_NAME))
  end
  
  def test_extractDirectoryExistsAsDir
    Dir.mkdir TEST_OUT_NAME
    extract_test_dir
    assert(File.directory?(TEST_OUT_NAME))
  end

  def test_extractDirectoryExistsAsFile
    File.open(TEST_OUT_NAME, "w") { |f| f.puts "something" }
    assert_raise(ZipDestinationFileExistsError) { extract_test_dir }
  end

  def test_extractDirectoryExistsAsFileOverwrite
    File.open(TEST_OUT_NAME, "w") { |f| f.puts "something" }
    gotCalled = false
    extract_test_dir { 
      |entry, destPath| 
      gotCalled = true
      assert_equal(TEST_OUT_NAME, destPath)
      assert(entry.is_directory)
      true
    }
    assert(gotCalled)
    assert(File.directory?(TEST_OUT_NAME))
  end
end

class ZipExtraFieldTest < Test::Unit::TestCase
  def test_new
    extra_pure    = ZipExtraField.new("")
    extra_withstr = ZipExtraField.new("foo")
    assert_instance_of(ZipExtraField, extra_pure)
    assert_instance_of(ZipExtraField, extra_withstr)
  end

  def test_unknownfield
    extra = ZipExtraField.new("foo")
    assert_equal(extra["Unknown"], "foo")
    extra.merge("a")
    assert_equal(extra["Unknown"], "fooa")
    extra.merge("barbaz")
    assert_equal(extra.to_s, "fooabarbaz")
  end


  def test_merge
    str = "UT\x5\0\x3\250$\r@Ux\0\0"
    extra1 = ZipExtraField.new("")
    extra2 = ZipExtraField.new(str)
    assert(! extra1.member?("UniversalTime"))
    assert(extra2.member?("UniversalTime"))
    extra1.merge(str)
    assert_equal(extra1["UniversalTime"].mtime, extra2["UniversalTime"].mtime)
  end

  def test_length
    str = "UT\x5\0\x3\250$\r@Ux\0\0Te\0\0testit"
    extra = ZipExtraField.new(str)
    assert_equal(extra.local_length, extra.to_local_bin.length)
    assert_equal(extra.c_dir_length, extra.to_c_dir_bin.length)
    extra.merge("foo")
    assert_equal(extra.local_length, extra.to_local_bin.length)
    assert_equal(extra.c_dir_length, extra.to_c_dir_bin.length)
  end


  def test_to_s
    str = "UT\x5\0\x3\250$\r@Ux\0\0Te\0\0testit"
    extra = ZipExtraField.new(str)
    assert_instance_of(String, extra.to_s)

    s = extra.to_s
    extra.merge("foo")
    assert_equal(s.length + 3, extra.to_s.length)
  end

  def test_equality
    str = "UT\x5\0\x3\250$\r@"
    extra1 = ZipExtraField.new(str)
    extra2 = ZipExtraField.new(str)
    extra3 = ZipExtraField.new(str)
    assert_equal(extra1, extra2)
   
    extra2["UniversalTime"].mtime = Time.now
    assert(extra1 != extra2)

    extra3.create("IUnix")
    assert(extra1 != extra3)

    extra1.create("IUnix")
    assert_equal(extra1, extra3)
  end

end

# Copyright (C) 2002-2005 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
