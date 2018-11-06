require 'test_helper'
require 'zip/filesystem'

class ZipFsFileStatTest < MiniTest::Test
  def setup
    @zip_file = ::Zip::File.new('test/data/zipWithDirs.zip')
  end

  def teardown
    @zip_file.close if @zip_file
  end

  def test_blocks
    assert_nil(@zip_file.file.stat('file1').blocks)
  end

  def test_ino
    assert_equal(0, @zip_file.file.stat('file1').ino)
  end

  def test_uid
    assert_equal(0, @zip_file.file.stat('file1').uid)
  end

  def test_gid
    assert_equal(0, @zip_file.file.stat('file1').gid)
  end

  def test_ftype
    assert_equal('file', @zip_file.file.stat('file1').ftype)
    assert_equal('directory', @zip_file.file.stat('dir1').ftype)
  end

  def test_mode
    assert_equal(0o600, @zip_file.file.stat('file1').mode & 0o777)
    assert_equal(0o600, @zip_file.file.stat('file1').mode & 0o777)
    assert_equal(0o755, @zip_file.file.stat('dir1').mode & 0o777)
    assert_equal(0o755, @zip_file.file.stat('dir1').mode & 0o777)
  end

  def test_dev
    assert_equal(0, @zip_file.file.stat('file1').dev)
  end

  def test_rdev
    assert_equal(0, @zip_file.file.stat('file1').rdev)
  end

  def test_rdev_major
    assert_equal(0, @zip_file.file.stat('file1').rdev_major)
  end

  def test_rdev_minor
    assert_equal(0, @zip_file.file.stat('file1').rdev_minor)
  end

  def test_nlink
    assert_equal(1, @zip_file.file.stat('file1').nlink)
  end

  def test_blksize
    assert_nil(@zip_file.file.stat('file1').blksize)
  end
end
