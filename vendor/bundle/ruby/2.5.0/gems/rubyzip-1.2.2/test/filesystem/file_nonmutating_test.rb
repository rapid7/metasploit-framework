require 'test_helper'
require 'zip/filesystem'

class ZipFsFileNonmutatingTest < MiniTest::Test
  def setup
    @zipsha = Digest::SHA1.file('test/data/zipWithDirs.zip')
    @zip_file = ::Zip::File.new('test/data/zipWithDirs.zip')
  end

  def teardown
    @zip_file.close if @zip_file
    assert_equal(@zipsha, Digest::SHA1.file('test/data/zipWithDirs.zip'))
  end

  def test_umask
    assert_equal(::File.umask, @zip_file.file.umask)
    @zip_file.file.umask(0o006)
  end

  def test_exists?
    assert(!@zip_file.file.exists?('notAFile'))
    assert(@zip_file.file.exists?('file1'))
    assert(@zip_file.file.exists?('dir1'))
    assert(@zip_file.file.exists?('dir1/'))
    assert(@zip_file.file.exists?('dir1/file12'))
    assert(@zip_file.file.exist?('dir1/file12')) # notice, tests exist? alias of exists? !

    @zip_file.dir.chdir 'dir1/'
    assert(!@zip_file.file.exists?('file1'))
    assert(@zip_file.file.exists?('file12'))
  end

  def test_open_read
    blockCalled = false
    @zip_file.file.open('file1', 'r') do |f|
      blockCalled = true
      assert_equal("this is the entry 'file1' in my test archive!",
                   f.readline.chomp)
    end
    assert(blockCalled)

    blockCalled = false
    @zip_file.file.open('file1', 'rb') do |f| # test binary flag is ignored
      blockCalled = true
      assert_equal("this is the entry 'file1' in my test archive!",
                   f.readline.chomp)
    end
    assert(blockCalled)

    blockCalled = false
    @zip_file.dir.chdir 'dir2'
    @zip_file.file.open('file21', 'r') do |f|
      blockCalled = true
      assert_equal("this is the entry 'dir2/file21' in my test archive!",
                   f.readline.chomp)
    end
    assert(blockCalled)
    @zip_file.dir.chdir '/'

    assert_raises(Errno::ENOENT) do
      @zip_file.file.open('noSuchEntry')
    end

    begin
      is = @zip_file.file.open('file1')
      assert_equal("this is the entry 'file1' in my test archive!",
                   is.readline.chomp)
    ensure
      is.close if is
    end
  end

  def test_new
    begin
      is = @zip_file.file.new('file1')
      assert_equal("this is the entry 'file1' in my test archive!",
                   is.readline.chomp)
    ensure
      is.close if is
    end
    begin
      is = @zip_file.file.new('file1') do
        fail 'should not call block'
      end
    ensure
      is.close if is
    end
  end

  def test_symlink
    assert_raises(NotImplementedError) do
      @zip_file.file.symlink('file1', 'aSymlink')
    end
  end

  def test_size
    assert_raises(Errno::ENOENT) { @zip_file.file.size('notAFile') }
    assert_equal(72, @zip_file.file.size('file1'))
    assert_equal(0, @zip_file.file.size('dir2/dir21'))

    assert_equal(72, @zip_file.file.stat('file1').size)
    assert_equal(0, @zip_file.file.stat('dir2/dir21').size)
  end

  def test_size?
    assert_nil(@zip_file.file.size?('notAFile'))
    assert_equal(72, @zip_file.file.size?('file1'))
    assert_nil(@zip_file.file.size?('dir2/dir21'))

    assert_equal(72, @zip_file.file.stat('file1').size?)
    assert_nil(@zip_file.file.stat('dir2/dir21').size?)
  end

  def test_file?
    assert(@zip_file.file.file?('file1'))
    assert(@zip_file.file.file?('dir2/file21'))
    assert(!@zip_file.file.file?('dir1'))
    assert(!@zip_file.file.file?('dir1/dir11'))

    assert(@zip_file.file.stat('file1').file?)
    assert(@zip_file.file.stat('dir2/file21').file?)
    assert(!@zip_file.file.stat('dir1').file?)
    assert(!@zip_file.file.stat('dir1/dir11').file?)
  end

  include ExtraAssertions

  def test_dirname
    assert_forwarded(File, :dirname, 'retVal', 'a/b/c/d') do
      @zip_file.file.dirname('a/b/c/d')
    end
  end

  def test_basename
    assert_forwarded(File, :basename, 'retVal', 'a/b/c/d') do
      @zip_file.file.basename('a/b/c/d')
    end
  end

  def test_split
    assert_forwarded(File, :split, 'retVal', 'a/b/c/d') do
      @zip_file.file.split('a/b/c/d')
    end
  end

  def test_join
    assert_equal('a/b/c', @zip_file.file.join('a/b', 'c'))
    assert_equal('a/b/c/d', @zip_file.file.join('a/b', 'c/d'))
    assert_equal('/c/d', @zip_file.file.join('', 'c/d'))
    assert_equal('a/b/c/d', @zip_file.file.join('a', 'b', 'c', 'd'))
  end

  def test_utime
    t_now = ::Zip::DOSTime.now
    t_bak = @zip_file.file.mtime('file1')
    @zip_file.file.utime(t_now, 'file1')
    assert_equal(t_now, @zip_file.file.mtime('file1'))
    @zip_file.file.utime(t_bak, 'file1')
    assert_equal(t_bak, @zip_file.file.mtime('file1'))
  end

  def assert_always_false(operation)
    assert(!@zip_file.file.send(operation, 'noSuchFile'))
    assert(!@zip_file.file.send(operation, 'file1'))
    assert(!@zip_file.file.send(operation, 'dir1'))
    assert(!@zip_file.file.stat('file1').send(operation))
    assert(!@zip_file.file.stat('dir1').send(operation))
  end

  def assert_true_if_entry_exists(operation)
    assert(!@zip_file.file.send(operation, 'noSuchFile'))
    assert(@zip_file.file.send(operation, 'file1'))
    assert(@zip_file.file.send(operation, 'dir1'))
    assert(@zip_file.file.stat('file1').send(operation))
    assert(@zip_file.file.stat('dir1').send(operation))
  end

  def test_pipe?
    assert_always_false(:pipe?)
  end

  def test_blockdev?
    assert_always_false(:blockdev?)
  end

  def test_symlink?
    assert_always_false(:symlink?)
  end

  def test_socket?
    assert_always_false(:socket?)
  end

  def test_chardev?
    assert_always_false(:chardev?)
  end

  def test_truncate
    assert_raises(StandardError, 'truncate not supported') do
      @zip_file.file.truncate('file1', 100)
    end
  end

  def assert_e_n_o_e_n_t(operation, args = ['NoSuchFile'])
    assert_raises(Errno::ENOENT) do
      @zip_file.file.send(operation, *args)
    end
  end

  def test_ftype
    assert_e_n_o_e_n_t(:ftype)
    assert_equal('file', @zip_file.file.ftype('file1'))
    assert_equal('directory', @zip_file.file.ftype('dir1/dir11'))
    assert_equal('directory', @zip_file.file.ftype('dir1/dir11/'))
  end

  def test_link
    assert_raises(NotImplementedError) do
      @zip_file.file.link('file1', 'someOtherString')
    end
  end

  def test_directory?
    assert(!@zip_file.file.directory?('notAFile'))
    assert(!@zip_file.file.directory?('file1'))
    assert(!@zip_file.file.directory?('dir1/file11'))
    assert(@zip_file.file.directory?('dir1'))
    assert(@zip_file.file.directory?('dir1/'))
    assert(@zip_file.file.directory?('dir2/dir21'))

    assert(!@zip_file.file.stat('file1').directory?)
    assert(!@zip_file.file.stat('dir1/file11').directory?)
    assert(@zip_file.file.stat('dir1').directory?)
    assert(@zip_file.file.stat('dir1/').directory?)
    assert(@zip_file.file.stat('dir2/dir21').directory?)
  end

  def test_chown
    assert_equal(2, @zip_file.file.chown(1, 2, 'dir1', 'file1'))
    assert_equal(1, @zip_file.file.stat('dir1').uid)
    assert_equal(2, @zip_file.file.stat('dir1').gid)
    assert_equal(2, @zip_file.file.chown(nil, nil, 'dir1', 'file1'))
  end

  def test_zero?
    assert(!@zip_file.file.zero?('notAFile'))
    assert(!@zip_file.file.zero?('file1'))
    assert(@zip_file.file.zero?('dir1'))
    blockCalled = false
    ::Zip::File.open('test/data/generated/5entry.zip') do |zf|
      blockCalled = true
      assert(zf.file.zero?('test/data/generated/empty.txt'))
    end
    assert(blockCalled)

    assert(!@zip_file.file.stat('file1').zero?)
    assert(@zip_file.file.stat('dir1').zero?)
    blockCalled = false
    ::Zip::File.open('test/data/generated/5entry.zip') do |zf|
      blockCalled = true
      assert(zf.file.stat('test/data/generated/empty.txt').zero?)
    end
    assert(blockCalled)
  end

  def test_expand_path
    ::Zip::File.open('test/data/zipWithDirs.zip') do |zf|
      assert_equal('/', zf.file.expand_path('.'))
      zf.dir.chdir 'dir1'
      assert_equal('/dir1', zf.file.expand_path('.'))
      assert_equal('/dir1/file12', zf.file.expand_path('file12'))
      assert_equal('/', zf.file.expand_path('..'))
      assert_equal('/dir2/dir21', zf.file.expand_path('../dir2/dir21'))
    end
  end

  def test_mtime
    assert_equal(::Zip::DOSTime.at(1_027_694_306),
                 @zip_file.file.mtime('dir2/file21'))
    assert_equal(::Zip::DOSTime.at(1_027_690_863),
                 @zip_file.file.mtime('dir2/dir21'))
    assert_raises(Errno::ENOENT) do
      @zip_file.file.mtime('noSuchEntry')
    end

    assert_equal(::Zip::DOSTime.at(1_027_694_306),
                 @zip_file.file.stat('dir2/file21').mtime)
    assert_equal(::Zip::DOSTime.at(1_027_690_863),
                 @zip_file.file.stat('dir2/dir21').mtime)
  end

  def test_ctime
    assert_nil(@zip_file.file.ctime('file1'))
    assert_nil(@zip_file.file.stat('file1').ctime)
  end

  def test_atime
    assert_nil(@zip_file.file.atime('file1'))
    assert_nil(@zip_file.file.stat('file1').atime)
  end

  def test_ntfs_time
    ::Zip::File.open('test/data/ntfs.zip') do |zf|
      t = ::Zip::DOSTime.at(1_410_496_497.405178)
      assert_equal(zf.file.mtime('data.txt'), t)
      assert_equal(zf.file.atime('data.txt'), t)
      assert_equal(zf.file.ctime('data.txt'), t)
    end
  end

  def test_readable?
    assert(!@zip_file.file.readable?('noSuchFile'))
    assert(@zip_file.file.readable?('file1'))
    assert(@zip_file.file.readable?('dir1'))
    assert(@zip_file.file.stat('file1').readable?)
    assert(@zip_file.file.stat('dir1').readable?)
  end

  def test_readable_real?
    assert(!@zip_file.file.readable_real?('noSuchFile'))
    assert(@zip_file.file.readable_real?('file1'))
    assert(@zip_file.file.readable_real?('dir1'))
    assert(@zip_file.file.stat('file1').readable_real?)
    assert(@zip_file.file.stat('dir1').readable_real?)
  end

  def test_writable?
    assert(!@zip_file.file.writable?('noSuchFile'))
    assert(@zip_file.file.writable?('file1'))
    assert(@zip_file.file.writable?('dir1'))
    assert(@zip_file.file.stat('file1').writable?)
    assert(@zip_file.file.stat('dir1').writable?)
  end

  def test_writable_real?
    assert(!@zip_file.file.writable_real?('noSuchFile'))
    assert(@zip_file.file.writable_real?('file1'))
    assert(@zip_file.file.writable_real?('dir1'))
    assert(@zip_file.file.stat('file1').writable_real?)
    assert(@zip_file.file.stat('dir1').writable_real?)
  end

  def test_executable?
    assert(!@zip_file.file.executable?('noSuchFile'))
    assert(!@zip_file.file.executable?('file1'))
    assert(@zip_file.file.executable?('dir1'))
    assert(!@zip_file.file.stat('file1').executable?)
    assert(@zip_file.file.stat('dir1').executable?)
  end

  def test_executable_real?
    assert(!@zip_file.file.executable_real?('noSuchFile'))
    assert(!@zip_file.file.executable_real?('file1'))
    assert(@zip_file.file.executable_real?('dir1'))
    assert(!@zip_file.file.stat('file1').executable_real?)
    assert(@zip_file.file.stat('dir1').executable_real?)
  end

  def test_owned?
    assert_true_if_entry_exists(:owned?)
  end

  def test_grpowned?
    assert_true_if_entry_exists(:grpowned?)
  end

  def test_setgid?
    assert_always_false(:setgid?)
  end

  def test_setuid?
    assert_always_false(:setgid?)
  end

  def test_sticky?
    assert_always_false(:sticky?)
  end

  def test_readlink
    assert_raises(NotImplementedError) do
      @zip_file.file.readlink('someString')
    end
  end

  def test_stat
    s = @zip_file.file.stat('file1')
    assert(s.kind_of?(File::Stat)) # It pretends
    assert_raises(Errno::ENOENT, 'No such file or directory - noSuchFile') do
      @zip_file.file.stat('noSuchFile')
    end
  end

  def test_lstat
    assert(@zip_file.file.lstat('file1').file?)
  end

  def test_pipe
    assert_raises(NotImplementedError) do
      @zip_file.file.pipe
    end
  end

  def test_foreach
    ::Zip::File.open('test/data/generated/zipWithDir.zip') do |zf|
      ref = []
      File.foreach('test/data/file1.txt') { |e| ref << e }
      index = 0

      zf.file.foreach('test/data/file1.txt') do |l|
        # Ruby replaces \n with \r\n automatically on windows
        newline = Zip::RUNNING_ON_WINDOWS ? l.gsub(/\r\n/, "\n") : l
        assert_equal(ref[index], newline)
        index = index.next
      end
      assert_equal(ref.size, index)
    end

    ::Zip::File.open('test/data/generated/zipWithDir.zip') do |zf|
      ref = []
      File.foreach('test/data/file1.txt', ' ') { |e| ref << e }
      index = 0

      zf.file.foreach('test/data/file1.txt', ' ') do |l|
        # Ruby replaces \n with \r\n automatically on windows
        newline = Zip::RUNNING_ON_WINDOWS ? l.gsub(/\r\n/, "\n") : l
        assert_equal(ref[index], newline)
        index = index.next
      end
      assert_equal(ref.size, index)
    end
  end

  def test_glob
    ::Zip::File.open('test/data/globTest.zip') do |zf|
      {
        'globTest/foo.txt' => ['globTest/foo.txt'],
        '*/foo.txt' => ['globTest/foo.txt'],
        '**/foo.txt' => ['globTest/foo.txt', 'globTest/foo/bar/baz/foo.txt'],
        '*/foo/**/*.txt' => ['globTest/foo/bar/baz/foo.txt']
      }.each do |spec, expected_results|
        results = zf.glob(spec)
        assert results.all? { |entry| entry.is_a? ::Zip::Entry }

        result_strings = results.map(&:to_s)
        missing_matches = expected_results - result_strings
        extra_matches = result_strings - expected_results

        assert extra_matches.empty?, "spec #{spec.inspect} has extra results #{extra_matches.inspect}"
        assert missing_matches.empty?, "spec #{spec.inspect} missing results #{missing_matches.inspect}"
      end
    end

    ::Zip::File.open('test/data/globTest.zip') do |zf|
      results = []
      zf.glob('**/foo.txt') do |match|
        results << "<#{match.class.name}: #{match}>"
      end
      assert(!results.empty?, 'block not run, or run out of context')
      assert_equal 2, results.size
      assert_operator results, :include?, '<Zip::Entry: globTest/foo.txt>'
      assert_operator results, :include?, '<Zip::Entry: globTest/foo/bar/baz/foo.txt>'
    end
  end

  def test_popen
    if Zip::RUNNING_ON_WINDOWS
      # This is pretty much projectile vomit but it allows the test to be
      # run on windows also
      system_dir = ::File.popen('dir') { |f| f.read }.gsub(/Dir\(s\).*$/, '')
      zipfile_dir = @zip_file.file.popen('dir') { |f| f.read }.gsub(/Dir\(s\).*$/, '')
      assert_equal(system_dir, zipfile_dir)
    else
      assert_equal(::File.popen('ls') { |f| f.read },
                   @zip_file.file.popen('ls') { |f| f.read })
    end
  end

  # Can be added later
  #  def test_select
  #    fail "implement test"
  #  end

  def test_readlines
    ::Zip::File.open('test/data/generated/zipWithDir.zip') do |zf|
      orig_file = ::File.readlines('test/data/file1.txt')
      zip_file = zf.file.readlines('test/data/file1.txt')

      # Ruby replaces \n with \r\n automatically on windows
      zip_file.each { |l| l.gsub!(/\r\n/, "\n") } if Zip::RUNNING_ON_WINDOWS

      assert_equal(orig_file, zip_file)
    end
  end

  def test_read
    ::Zip::File.open('test/data/generated/zipWithDir.zip') do |zf|
      orig_file = ::File.read('test/data/file1.txt')

      # Ruby replaces \n with \r\n automatically on windows
      zip_file = if Zip::RUNNING_ON_WINDOWS
                   zf.file.read('test/data/file1.txt').gsub(/\r\n/, "\n")
                 else
                   zf.file.read('test/data/file1.txt')
                 end
      assert_equal(orig_file, zip_file)
    end
  end
end
