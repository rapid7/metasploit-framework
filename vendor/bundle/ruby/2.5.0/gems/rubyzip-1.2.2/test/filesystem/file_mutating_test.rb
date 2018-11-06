require 'test_helper'
require 'zip/filesystem'

class ZipFsFileMutatingTest < MiniTest::Test
  TEST_ZIP = 'test/data/generated/zipWithDirs_copy.zip'
  def setup
    FileUtils.cp('test/data/zipWithDirs.zip', TEST_ZIP)
  end

  def teardown; end

  def test_delete
    do_test_delete_or_unlink(:delete)
  end

  def test_unlink
    do_test_delete_or_unlink(:unlink)
  end

  def test_open_write
    ::Zip::File.open(TEST_ZIP) do |zf|
      zf.file.open('test_open_write_entry', 'w') do |f|
        f.write "This is what I'm writing"
      end
      assert_equal("This is what I'm writing",
                   zf.file.read('test_open_write_entry'))

      # Test with existing entry
      zf.file.open('file1', 'wb') do |f| # also check that 'b' option is ignored
        f.write "This is what I'm writing too"
      end
      assert_equal("This is what I'm writing too",
                   zf.file.read('file1'))
    end
  end

  def test_rename
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_raises(Errno::ENOENT, '') do
        zf.file.rename('NoSuchFile', 'bimse')
      end
      zf.file.rename('file1', 'newNameForFile1')
    end

    ::Zip::File.open(TEST_ZIP) do |zf|
      assert(!zf.file.exists?('file1'))
      assert(zf.file.exists?('newNameForFile1'))
    end
  end

  def test_chmod
    ::Zip::File.open(TEST_ZIP) do |zf|
      zf.file.chmod(0o765, 'file1')
    end

    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_equal(0o100765, zf.file.stat('file1').mode)
    end
  end

  def do_test_delete_or_unlink(symbol)
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert(zf.file.exists?('dir2/dir21/dir221/file2221'))
      zf.file.send(symbol, 'dir2/dir21/dir221/file2221')
      assert(!zf.file.exists?('dir2/dir21/dir221/file2221'))

      assert(zf.file.exists?('dir1/file11'))
      assert(zf.file.exists?('dir1/file12'))
      zf.file.send(symbol, 'dir1/file11', 'dir1/file12')
      assert(!zf.file.exists?('dir1/file11'))
      assert(!zf.file.exists?('dir1/file12'))

      assert_raises(Errno::ENOENT) { zf.file.send(symbol, 'noSuchFile') }
      assert_raises(Errno::EISDIR) { zf.file.send(symbol, 'dir1/dir11') }
      assert_raises(Errno::EISDIR) { zf.file.send(symbol, 'dir1/dir11/') }
    end

    ::Zip::File.open(TEST_ZIP) do |zf|
      assert(!zf.file.exists?('dir2/dir21/dir221/file2221'))
      assert(!zf.file.exists?('dir1/file11'))
      assert(!zf.file.exists?('dir1/file12'))

      assert(zf.file.exists?('dir1/dir11'))
      assert(zf.file.exists?('dir1/dir11/'))
    end
  end
end
