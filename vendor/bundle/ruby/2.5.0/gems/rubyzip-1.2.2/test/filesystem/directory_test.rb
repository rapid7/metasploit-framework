require 'test_helper'
require 'zip/filesystem'

class ZipFsDirectoryTest < MiniTest::Test
  TEST_ZIP = 'test/data/generated/zipWithDirs_copy.zip'
  GLOB_TEST_ZIP = 'test/data/globTest.zip'

  def setup
    FileUtils.cp('test/data/zipWithDirs.zip', TEST_ZIP)
  end

  def test_delete
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_raises(Errno::ENOENT, 'No such file or directory - NoSuchFile.txt') do
        zf.dir.delete('NoSuchFile.txt')
      end
      assert_raises(Errno::EINVAL, 'Invalid argument - file1') do
        zf.dir.delete('file1')
      end
      assert(zf.file.exists?('dir1'))
      zf.dir.delete('dir1')
      assert(!zf.file.exists?('dir1'))
    end
  end

  def test_mkdir
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_raises(Errno::EEXIST, 'File exists - dir1') do
        zf.dir.mkdir('file1')
      end
      assert_raises(Errno::EEXIST, 'File exists - dir1') do
        zf.dir.mkdir('dir1')
      end
      assert(!zf.file.exists?('newDir'))
      zf.dir.mkdir('newDir')
      assert(zf.file.directory?('newDir'))
      assert(!zf.file.exists?('newDir2'))
      zf.dir.mkdir('newDir2', 3485)
      assert(zf.file.directory?('newDir2'))
    end
  end

  def test_pwd_chdir_entries
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_equal('/', zf.dir.pwd)

      assert_raises(Errno::ENOENT, 'No such file or directory - no such dir') do
        zf.dir.chdir 'no such dir'
      end

      assert_raises(Errno::EINVAL, 'Invalid argument - file1') do
        zf.dir.chdir 'file1'
      end

      assert_equal(%w[dir1 dir2 file1].sort, zf.dir.entries('.').sort)
      zf.dir.chdir 'dir1'
      assert_equal('/dir1', zf.dir.pwd)
      assert_equal(%w[dir11 file11 file12], zf.dir.entries('.').sort)

      zf.dir.chdir '../dir2/dir21'
      assert_equal('/dir2/dir21', zf.dir.pwd)
      assert_equal(['dir221'].sort, zf.dir.entries('.').sort)
    end
  end

  def test_foreach
    ::Zip::File.open(TEST_ZIP) do |zf|
      blockCalled = false
      assert_raises(Errno::ENOENT, 'No such file or directory - noSuchDir') do
        zf.dir.foreach('noSuchDir') { |_e| blockCalled = true }
      end
      assert(!blockCalled)

      assert_raises(Errno::ENOTDIR, 'Not a directory - file1') do
        zf.dir.foreach('file1') { |_e| blockCalled = true }
      end
      assert(!blockCalled)

      entries = []
      zf.dir.foreach('.') { |e| entries << e }
      assert_equal(%w[dir1 dir2 file1].sort, entries.sort)

      entries = []
      zf.dir.foreach('dir1') { |e| entries << e }
      assert_equal(%w[dir11 file11 file12], entries.sort)
    end
  end

  def test_chroot
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_raises(NotImplementedError) do
        zf.dir.chroot
      end
    end
  end

  def test_glob
    globbed_files = [
      'globTest/foo/bar/baz/foo.txt',
      'globTest/foo.txt',
      'globTest/food.txt'
    ]

    ::Zip::File.open(GLOB_TEST_ZIP) do |zf|
      zf.dir.glob('**/*.txt') do |f|
        assert globbed_files.include?(f.name)
      end

      zf.dir.glob('globTest/foo/**/*.txt') do |f|
        assert_equal globbed_files[0], f.name
      end

      zf.dir.chdir('globTest/foo')
      zf.dir.glob('**/*.txt') do |f|
        assert_equal globbed_files[0], f.name
      end
    end
  end

  def test_open_new
    ::Zip::File.open(TEST_ZIP) do |zf|
      assert_raises(Errno::ENOTDIR, 'Not a directory - file1') do
        zf.dir.new('file1')
      end

      assert_raises(Errno::ENOENT, 'No such file or directory - noSuchFile') do
        zf.dir.new('noSuchFile')
      end

      d = zf.dir.new('.')
      assert_equal(%w[file1 dir1 dir2].sort, d.entries.sort)
      d.close

      zf.dir.open('dir1') do |dir|
        assert_equal(%w[dir11 file11 file12].sort, dir.entries.sort)
      end
    end
  end
end
