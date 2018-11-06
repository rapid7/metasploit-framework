require 'test_helper'

class ZipFileExtractDirectoryTest < MiniTest::Test
  include CommonZipFileFixture

  TEST_OUT_NAME = 'test/data/generated/emptyOutDir'

  def open_zip(&aProc)
    assert(!aProc.nil?)
    ::Zip::File.open(TestZipFile::TEST_ZIP4.zip_name, &aProc)
  end

  def extract_test_dir(&aProc)
    open_zip do |zf|
      zf.extract(TestFiles::EMPTY_TEST_DIR, TEST_OUT_NAME, &aProc)
    end
  end

  def setup
    super

    Dir.rmdir(TEST_OUT_NAME) if File.directory? TEST_OUT_NAME
    File.delete(TEST_OUT_NAME) if File.exist? TEST_OUT_NAME
  end

  def test_extract_directory
    extract_test_dir
    assert(File.directory?(TEST_OUT_NAME))
  end

  def test_extract_directory_exists_as_dir
    Dir.mkdir TEST_OUT_NAME
    extract_test_dir
    assert(File.directory?(TEST_OUT_NAME))
  end

  def test_extract_directory_exists_as_file
    File.open(TEST_OUT_NAME, 'w') { |f| f.puts 'something' }
    assert_raises(::Zip::DestinationFileExistsError) { extract_test_dir }
  end

  def test_extract_directory_exists_as_file_overwrite
    File.open(TEST_OUT_NAME, 'w') { |f| f.puts 'something' }
    gotCalled = false
    extract_test_dir do |entry, destPath|
      gotCalled = true
      assert_equal(TEST_OUT_NAME, destPath)
      assert(entry.directory?)
      true
    end
    assert(gotCalled)
    assert(File.directory?(TEST_OUT_NAME))
  end
end
