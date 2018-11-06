require 'test_helper'

class ZipCaseSensitivityTest < MiniTest::Test
  include CommonZipFileFixture

  SRC_FILES = [['test/data/file1.txt', 'testfile.rb'],
               ['test/data/file2.txt', 'testFILE.rb']]

  def teardown
    ::Zip.case_insensitive_match = false
  end

  # Ensure that everything functions normally when +case_insensitive_match = false+
  def test_add_case_sensitive
    ::Zip.case_insensitive_match = false

    SRC_FILES.each { |fn, _en| assert(::File.exist?(fn)) }
    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)

    SRC_FILES.each { |fn, en| zf.add(en, fn) }
    zf.close

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal(SRC_FILES.size, zfRead.entries.length)
    SRC_FILES.each_with_index { |a, i|
      assert_equal(a.last, zfRead.entries[i].name)
      AssertEntry.assert_contents(a.first,
                                  zfRead.get_input_stream(a.last) { |zis| zis.read })
    }
  end

  # Ensure that names are treated case insensitively when adding files and +case_insensitive_match = false+
  def test_add_case_insensitive
    ::Zip.case_insensitive_match = true

    SRC_FILES.each { |fn, _en| assert(::File.exist?(fn)) }
    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)

    assert_raises Zip::EntryExistsError do
      SRC_FILES.each { |fn, en| zf.add(en, fn) }
    end
  end

  # Ensure that names are treated case insensitively when reading files and +case_insensitive_match = true+
  def test_add_case_sensitive_read_case_insensitive
    ::Zip.case_insensitive_match = false

    SRC_FILES.each { |fn, _en| assert(::File.exist?(fn)) }
    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)

    SRC_FILES.each { |fn, en| zf.add(en, fn) }
    zf.close

    ::Zip.case_insensitive_match = true

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal(SRC_FILES.collect { |_fn, en| en.downcase }.uniq.size, zfRead.entries.length)
    assert_equal(SRC_FILES.last.last.downcase, zfRead.entries.first.name.downcase)
    AssertEntry.assert_contents(SRC_FILES.last.first,
                                zfRead.get_input_stream(SRC_FILES.last.last) { |zis| zis.read })
  end

  private

  def assert_contains(zf, entryName, filename = entryName)
    assert(zf.entries.detect { |e| e.name == entryName } != nil, "entry #{entryName} not in #{zf.entries.join(', ')} in zip file #{zf}")
    assert_entry_contents(zf, entryName, filename) if File.exist?(filename)
  end
end
