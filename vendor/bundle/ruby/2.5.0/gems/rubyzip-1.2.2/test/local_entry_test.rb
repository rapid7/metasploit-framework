require 'test_helper'

class ZipLocalEntryTest < MiniTest::Test
  CEH_FILE = 'test/data/generated/centralEntryHeader.bin'
  LEH_FILE = 'test/data/generated/localEntryHeader.bin'

  def teardown
    ::Zip.write_zip64_support = false
  end

  def test_read_local_entry_header_of_first_test_zip_entry
    ::File.open(TestZipFile::TEST_ZIP3.zip_name, 'rb') do |file|
      entry = ::Zip::Entry.read_local_entry(file)

      assert_equal('', entry.comment)
      # Differs from windows and unix because of CR LF
      # assert_equal(480, entry.compressed_size)
      # assert_equal(0x2a27930f, entry.crc)
      # extra field is 21 bytes long
      # probably contains some unix attrutes or something
      # disabled: assert_equal(nil, entry.extra)
      assert_equal(::Zip::Entry::DEFLATED, entry.compression_method)
      assert_equal(TestZipFile::TEST_ZIP3.entry_names[0], entry.name)
      assert_equal(::File.size(TestZipFile::TEST_ZIP3.entry_names[0]), entry.size)
      assert(!entry.directory?)
    end
  end

  def test_read_date_time
    ::File.open('test/data/rubycode.zip', 'rb') do |file|
      entry = ::Zip::Entry.read_local_entry(file)
      assert_equal('zippedruby1.rb', entry.name)
      assert_equal(::Zip::DOSTime.at(1_019_261_638), entry.time)
    end
  end

  def test_read_local_entry_from_non_zip_file
    ::File.open('test/data/file2.txt') do |file|
      assert_nil(::Zip::Entry.read_local_entry(file))
    end
  end

  def test_read_local_entry_from_truncated_zip_file
    zipFragment = ''
    ::File.open(TestZipFile::TEST_ZIP2.zip_name) { |f| zipFragment = f.read(12) } # local header is at least 30 bytes
    zipFragment.extend(IOizeString).reset
    entry = ::Zip::Entry.new
    entry.read_local_entry(zipFragment)
    fail 'ZipError expected'
  rescue ::Zip::Error
  end

  def test_write_entry
    entry = ::Zip::Entry.new('file.zip', 'entryName', 'my little comment',
                             'thisIsSomeExtraInformation', 100, 987_654,
                             ::Zip::Entry::DEFLATED, 400)
    write_to_file(LEH_FILE, CEH_FILE, entry)
    entryReadLocal, entryReadCentral = read_from_file(LEH_FILE, CEH_FILE)
    assert(entryReadCentral.extra['Zip64Placeholder'].nil?, 'zip64 placeholder should not be used in central directory')
    compare_local_entry_headers(entry, entryReadLocal)
    compare_c_dir_entry_headers(entry, entryReadCentral)
  end

  def test_write_entry_with_zip64
    ::Zip.write_zip64_support = true
    entry = ::Zip::Entry.new('file.zip', 'entryName', 'my little comment',
                             'thisIsSomeExtraInformation', 100, 987_654,
                             ::Zip::Entry::DEFLATED, 400)
    write_to_file(LEH_FILE, CEH_FILE, entry)
    entryReadLocal, entryReadCentral = read_from_file(LEH_FILE, CEH_FILE)
    assert(entryReadLocal.extra['Zip64Placeholder'], 'zip64 placeholder should be used in local file header')
    entryReadLocal.extra.delete('Zip64Placeholder') # it was removed when writing the c_dir_entry, so remove from compare
    assert(entryReadCentral.extra['Zip64Placeholder'].nil?, 'zip64 placeholder should not be used in central directory')
    compare_local_entry_headers(entry, entryReadLocal)
    compare_c_dir_entry_headers(entry, entryReadCentral)
  end

  def test_write_64entry
    ::Zip.write_zip64_support = true
    entry = ::Zip::Entry.new('bigfile.zip', 'entryName', 'my little equine',
                             'malformed extra field because why not',
                             0x7766554433221100, 0xDEADBEEF, ::Zip::Entry::DEFLATED,
                             0x9988776655443322)
    write_to_file(LEH_FILE, CEH_FILE, entry)
    entryReadLocal, entryReadCentral = read_from_file(LEH_FILE, CEH_FILE)
    compare_local_entry_headers(entry, entryReadLocal)
    compare_c_dir_entry_headers(entry, entryReadCentral)
  end

  def test_rewrite_local_header64
    ::Zip.write_zip64_support = true
    buf1 = StringIO.new
    entry = ::Zip::Entry.new('file.zip', 'entryName')
    entry.write_local_entry(buf1)
    assert(entry.extra['Zip64'].nil?, 'zip64 extra is unnecessarily present')

    buf2 = StringIO.new
    entry.size = 0x123456789ABCDEF0
    entry.compressed_size = 0x0123456789ABCDEF
    entry.write_local_entry(buf2, true)
    refute_nil(entry.extra['Zip64'])
    refute_equal(buf1.size, 0)
    assert_equal(buf1.size, buf2.size) # it can't grow, or we'd clobber file data
  end

  def test_read_local_offset
    entry = ::Zip::Entry.new('file.zip', 'entryName')
    entry.local_header_offset = 12_345
    ::File.open(CEH_FILE, 'wb') { |f| entry.write_c_dir_entry(f) }
    read_entry = nil
    ::File.open(CEH_FILE, 'rb') { |f| read_entry = ::Zip::Entry.read_c_dir_entry(f) }
    compare_c_dir_entry_headers(entry, read_entry)
  end

  def test_read64_local_offset
    ::Zip.write_zip64_support = true
    entry = ::Zip::Entry.new('file.zip', 'entryName')
    entry.local_header_offset = 0x0123456789ABCDEF
    ::File.open(CEH_FILE, 'wb') { |f| entry.write_c_dir_entry(f) }
    read_entry = nil
    ::File.open(CEH_FILE, 'rb') { |f| read_entry = ::Zip::Entry.read_c_dir_entry(f) }
    compare_c_dir_entry_headers(entry, read_entry)
  end

  private

  def compare_local_entry_headers(entry1, entry2)
    assert_equal(entry1.compressed_size, entry2.compressed_size)
    assert_equal(entry1.crc, entry2.crc)
    assert_equal(entry1.extra, entry2.extra)
    assert_equal(entry1.compression_method, entry2.compression_method)
    assert_equal(entry1.name, entry2.name)
    assert_equal(entry1.size, entry2.size)
    assert_equal(entry1.local_header_offset, entry2.local_header_offset)
  end

  def compare_c_dir_entry_headers(entry1, entry2)
    compare_local_entry_headers(entry1, entry2)
    assert_equal(entry1.comment, entry2.comment)
  end

  def write_to_file(localFileName, centralFileName, entry)
    ::File.open(localFileName, 'wb') { |f| entry.write_local_entry(f) }
    ::File.open(centralFileName, 'wb') { |f| entry.write_c_dir_entry(f) }
  end

  def read_from_file(localFileName, centralFileName)
    localEntry = nil
    cdirEntry = nil
    ::File.open(localFileName, 'rb') { |f| localEntry = ::Zip::Entry.read_local_entry(f) }
    ::File.open(centralFileName, 'rb') { |f| cdirEntry = ::Zip::Entry.read_c_dir_entry(f) }
    [localEntry, cdirEntry]
  end
end
