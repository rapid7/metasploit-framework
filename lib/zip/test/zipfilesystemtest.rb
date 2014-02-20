#!/usr/bin/env ruby

$VERBOSE = true

$: << "../lib"

require 'zip/zipfilesystem'
require 'test/unit'
require 'fileutils'

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

include Zip

class ZipFsFileNonmutatingTest < Test::Unit::TestCase
  def setup
    @zipFile = ZipFile.new("data/zipWithDirs.zip")
  end

  def teardown
    @zipFile.close if @zipFile
  end

  def test_umask
    assert_equal(File.umask, @zipFile.file.umask)
    @zipFile.file.umask(0006)
  end

  def test_exists?
    assert(! @zipFile.file.exists?("notAFile"))
    assert(@zipFile.file.exists?("file1"))
    assert(@zipFile.file.exists?("dir1"))
    assert(@zipFile.file.exists?("dir1/"))
    assert(@zipFile.file.exists?("dir1/file12"))
    assert(@zipFile.file.exist?("dir1/file12")) # notice, tests exist? alias of exists? !

    @zipFile.dir.chdir "dir1/"
    assert(!@zipFile.file.exists?("file1"))
    assert(@zipFile.file.exists?("file12"))
  end

  def test_open_read
    blockCalled = false
    @zipFile.file.open("file1", "r") {
      |f|
      blockCalled = true
      assert_equal("this is the entry 'file1' in my test archive!", 
        f.readline.chomp)
    }
    assert(blockCalled)

    blockCalled = false
    @zipFile.file.open("file1", "rb") { # test binary flag is ignored
      |f|
      blockCalled = true
      assert_equal("this is the entry 'file1' in my test archive!", 
        f.readline.chomp)
    }
    assert(blockCalled)

    blockCalled = false
    @zipFile.dir.chdir "dir2"
    @zipFile.file.open("file21", "r") {
      |f|
      blockCalled = true
      assert_equal("this is the entry 'dir2/file21' in my test archive!", 
        f.readline.chomp)
    }
    assert(blockCalled)
    @zipFile.dir.chdir "/"
    
    assert_raise(Errno::ENOENT) {
      @zipFile.file.open("noSuchEntry")
    }

    begin
      is = @zipFile.file.open("file1")
      assert_equal("this is the entry 'file1' in my test archive!", 
        is.readline.chomp)
    ensure
      is.close if is
    end
  end

  def test_new
    begin
      is = @zipFile.file.new("file1")
      assert_equal("this is the entry 'file1' in my test archive!", 
        is.readline.chomp)
    ensure
      is.close if is
    end
    begin
      is = @zipFile.file.new("file1") {
  fail "should not call block"
      }
    ensure
      is.close if is
    end
  end

  def test_symlink
    assert_raise(NotImplementedError) {
      @zipFile.file.symlink("file1", "aSymlink")
    }
  end
  
  def test_size
    assert_raise(Errno::ENOENT) { @zipFile.file.size("notAFile") }
    assert_equal(72, @zipFile.file.size("file1"))
    assert_equal(0, @zipFile.file.size("dir2/dir21"))

    assert_equal(72, @zipFile.file.stat("file1").size)
    assert_equal(0, @zipFile.file.stat("dir2/dir21").size)
  end

  def test_size?
    assert_equal(nil, @zipFile.file.size?("notAFile"))
    assert_equal(72, @zipFile.file.size?("file1"))
    assert_equal(nil, @zipFile.file.size?("dir2/dir21"))

    assert_equal(72, @zipFile.file.stat("file1").size?)
    assert_equal(nil, @zipFile.file.stat("dir2/dir21").size?)
  end


  def test_file?
    assert(@zipFile.file.file?("file1"))
    assert(@zipFile.file.file?("dir2/file21"))
    assert(! @zipFile.file.file?("dir1"))
    assert(! @zipFile.file.file?("dir1/dir11"))

    assert(@zipFile.file.stat("file1").file?)
    assert(@zipFile.file.stat("dir2/file21").file?)
    assert(! @zipFile.file.stat("dir1").file?)
    assert(! @zipFile.file.stat("dir1/dir11").file?)
  end

  include ExtraAssertions

  def test_dirname
    assert_forwarded(File, :dirname, "retVal", "a/b/c/d") { 
      @zipFile.file.dirname("a/b/c/d")
    }
  end

  def test_basename
    assert_forwarded(File, :basename, "retVal", "a/b/c/d") { 
      @zipFile.file.basename("a/b/c/d")
    }
  end

  def test_split
    assert_forwarded(File, :split, "retVal", "a/b/c/d") { 
      @zipFile.file.split("a/b/c/d")
    }
  end

  def test_join
    assert_equal("a/b/c", @zipFile.file.join("a/b", "c"))
    assert_equal("a/b/c/d", @zipFile.file.join("a/b", "c/d"))
    assert_equal("/c/d", @zipFile.file.join("", "c/d"))
    assert_equal("a/b/c/d", @zipFile.file.join("a", "b", "c", "d"))
  end

  def test_utime
    t_now = Time.now
    t_bak = @zipFile.file.mtime("file1")
    @zipFile.file.utime(t_now, "file1")
    assert_equal(t_now, @zipFile.file.mtime("file1"))
    @zipFile.file.utime(t_bak, "file1")
    assert_equal(t_bak, @zipFile.file.mtime("file1"))
  end


  def assert_always_false(operation)
    assert(! @zipFile.file.send(operation, "noSuchFile"))
    assert(! @zipFile.file.send(operation, "file1"))
    assert(! @zipFile.file.send(operation, "dir1"))
    assert(! @zipFile.file.stat("file1").send(operation))
    assert(! @zipFile.file.stat("dir1").send(operation))
  end

  def assert_true_if_entry_exists(operation)
    assert(! @zipFile.file.send(operation, "noSuchFile"))
    assert(@zipFile.file.send(operation, "file1"))
    assert(@zipFile.file.send(operation, "dir1"))
    assert(@zipFile.file.stat("file1").send(operation))
    assert(@zipFile.file.stat("dir1").send(operation))
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
    assert_raise(StandardError, "truncate not supported") {
      @zipFile.file.truncate("file1", 100)
    }
  end

  def assert_e_n_o_e_n_t(operation, args = ["NoSuchFile"])
    assert_raise(Errno::ENOENT) {
      @zipFile.file.send(operation, *args)
    }
  end

  def test_ftype
    assert_e_n_o_e_n_t(:ftype)
    assert_equal("file", @zipFile.file.ftype("file1"))
    assert_equal("directory", @zipFile.file.ftype("dir1/dir11"))
    assert_equal("directory", @zipFile.file.ftype("dir1/dir11/"))
  end

  def test_link
    assert_raise(NotImplementedError) {
      @zipFile.file.link("file1", "someOtherString")
    }
  end

  def test_directory?
    assert(! @zipFile.file.directory?("notAFile"))
    assert(! @zipFile.file.directory?("file1"))
    assert(! @zipFile.file.directory?("dir1/file11"))
    assert(@zipFile.file.directory?("dir1"))
    assert(@zipFile.file.directory?("dir1/"))
    assert(@zipFile.file.directory?("dir2/dir21"))

    assert(! @zipFile.file.stat("file1").directory?)
    assert(! @zipFile.file.stat("dir1/file11").directory?)
    assert(@zipFile.file.stat("dir1").directory?)
    assert(@zipFile.file.stat("dir1/").directory?)
    assert(@zipFile.file.stat("dir2/dir21").directory?)
  end

  def test_chown
    assert_equal(2, @zipFile.file.chown(1,2, "dir1", "file1"))
    assert_equal(1, @zipFile.file.stat("dir1").uid)
    assert_equal(2, @zipFile.file.stat("dir1").gid)
    assert_equal(2, @zipFile.file.chown(nil, nil, "dir1", "file1"))
  end

  def test_zero?
    assert(! @zipFile.file.zero?("notAFile"))
    assert(! @zipFile.file.zero?("file1"))
    assert(@zipFile.file.zero?("dir1"))
    blockCalled = false
    ZipFile.open("data/generated/5entry.zip") {
      |zf|
      blockCalled = true
      assert(zf.file.zero?("data/generated/empty.txt"))
    }
    assert(blockCalled)

    assert(! @zipFile.file.stat("file1").zero?)
    assert(@zipFile.file.stat("dir1").zero?)
    blockCalled = false
    ZipFile.open("data/generated/5entry.zip") {
      |zf|
      blockCalled = true
      assert(zf.file.stat("data/generated/empty.txt").zero?)
    }
    assert(blockCalled)
  end

  def test_expand_path
    ZipFile.open("data/zipWithDirs.zip") {
      |zf|
      assert_equal("/", zf.file.expand_path("."))
      zf.dir.chdir "dir1"
      assert_equal("/dir1", zf.file.expand_path("."))
      assert_equal("/dir1/file12", zf.file.expand_path("file12"))
      assert_equal("/", zf.file.expand_path(".."))
      assert_equal("/dir2/dir21", zf.file.expand_path("../dir2/dir21"))
    }
  end

  def test_mtime
    assert_equal(Time.at(1027694306),
      @zipFile.file.mtime("dir2/file21"))
    assert_equal(Time.at(1027690863),
      @zipFile.file.mtime("dir2/dir21"))
    assert_raise(Errno::ENOENT) {
      @zipFile.file.mtime("noSuchEntry")
    }

    assert_equal(Time.at(1027694306),
      @zipFile.file.stat("dir2/file21").mtime)
    assert_equal(Time.at(1027690863),
      @zipFile.file.stat("dir2/dir21").mtime)
  end

  def test_ctime
    assert_nil(@zipFile.file.ctime("file1"))
    assert_nil(@zipFile.file.stat("file1").ctime)
  end

  def test_atime
    assert_nil(@zipFile.file.atime("file1"))
    assert_nil(@zipFile.file.stat("file1").atime)
  end

  def test_readable?
    assert(! @zipFile.file.readable?("noSuchFile"))
    assert(@zipFile.file.readable?("file1"))
    assert(@zipFile.file.readable?("dir1"))
    assert(@zipFile.file.stat("file1").readable?)
    assert(@zipFile.file.stat("dir1").readable?)
  end

  def test_readable_real?
    assert(! @zipFile.file.readable_real?("noSuchFile"))
    assert(@zipFile.file.readable_real?("file1"))
    assert(@zipFile.file.readable_real?("dir1"))
    assert(@zipFile.file.stat("file1").readable_real?)
    assert(@zipFile.file.stat("dir1").readable_real?)
  end

  def test_writable?
    assert(! @zipFile.file.writable?("noSuchFile"))
    assert(@zipFile.file.writable?("file1"))
    assert(@zipFile.file.writable?("dir1"))
    assert(@zipFile.file.stat("file1").writable?)
    assert(@zipFile.file.stat("dir1").writable?)
  end

  def test_writable_real?
    assert(! @zipFile.file.writable_real?("noSuchFile"))
    assert(@zipFile.file.writable_real?("file1"))
    assert(@zipFile.file.writable_real?("dir1"))
    assert(@zipFile.file.stat("file1").writable_real?)
    assert(@zipFile.file.stat("dir1").writable_real?)
  end

  def test_executable?
    assert(! @zipFile.file.executable?("noSuchFile"))
    assert(! @zipFile.file.executable?("file1"))
    assert(@zipFile.file.executable?("dir1"))
    assert(! @zipFile.file.stat("file1").executable?)
    assert(@zipFile.file.stat("dir1").executable?)
  end

  def test_executable_real?
    assert(! @zipFile.file.executable_real?("noSuchFile"))
    assert(! @zipFile.file.executable_real?("file1"))
    assert(@zipFile.file.executable_real?("dir1"))
    assert(! @zipFile.file.stat("file1").executable_real?)
    assert(@zipFile.file.stat("dir1").executable_real?)
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
    assert_raise(NotImplementedError) {
      @zipFile.file.readlink("someString")
    }
  end

  def test_stat
    s = @zipFile.file.stat("file1")
    assert(s.kind_of?(File::Stat)) # It pretends
    assert_raise(Errno::ENOENT, "No such file or directory - noSuchFile") {
      @zipFile.file.stat("noSuchFile")
    }
  end

  def test_lstat
    assert(@zipFile.file.lstat("file1").file?)
  end


  def test_chmod
    assert_raise(Errno::ENOENT, "No such file or directory - noSuchFile") {
      @zipFile.file.chmod(0644, "file1", "NoSuchFile")
    }
    assert_equal(2, @zipFile.file.chmod(0644, "file1", "dir1"))
  end

  def test_pipe
    assert_raise(NotImplementedError) {
      @zipFile.file.pipe
    }
  end

  def test_foreach
    ZipFile.open("data/generated/zipWithDir.zip") {
      |zf|
      ref = []
      File.foreach("data/file1.txt") { |e| ref << e }
      
      index = 0
      zf.file.foreach("data/file1.txt") { 
  |l|
  assert_equal(ref[index], l)
  index = index.next
      }
      assert_equal(ref.size, index)
    }
    
    ZipFile.open("data/generated/zipWithDir.zip") {
      |zf|
      ref = []
      File.foreach("data/file1.txt", " ") { |e| ref << e }
      
      index = 0
      zf.file.foreach("data/file1.txt", " ") { 
  |l|
  assert_equal(ref[index], l)
  index = index.next
      }
      assert_equal(ref.size, index)
    }
  end

  def test_popen
    if RUBY_PLATFORM =~ /mswin|mingw/i
      cmd = 'dir'
    else
      cmd = 'ls'
    end

    assert_equal(File.popen(cmd)          { |f| f.read }, 
      @zipFile.file.popen(cmd) { |f| f.read })
  end

# Can be added later
#  def test_select
#    fail "implement test"
#  end

  def test_readlines
    ZipFile.open("data/generated/zipWithDir.zip") {
      |zf|
      assert_equal(File.readlines("data/file1.txt"), 
        zf.file.readlines("data/file1.txt"))
    }
  end

  def test_read
    ZipFile.open("data/generated/zipWithDir.zip") {
      |zf|
      assert_equal(File.read("data/file1.txt"), 
        zf.file.read("data/file1.txt"))
    }
  end

end

class ZipFsFileStatTest < Test::Unit::TestCase

  def setup
    @zipFile = ZipFile.new("data/zipWithDirs.zip")
  end

  def teardown
    @zipFile.close if @zipFile
  end

  def test_blocks
    assert_equal(nil, @zipFile.file.stat("file1").blocks)
  end

  def test_ino
    assert_equal(0, @zipFile.file.stat("file1").ino)
  end

  def test_uid
    assert_equal(0, @zipFile.file.stat("file1").uid)
  end

  def test_gid
    assert_equal(0, @zipFile.file.stat("file1").gid)
  end

  def test_ftype
    assert_equal("file", @zipFile.file.stat("file1").ftype)
    assert_equal("directory", @zipFile.file.stat("dir1").ftype)
  end

  def test_mode
    assert_equal(0600, @zipFile.file.stat("file1").mode & 0777)
    assert_equal(0600, @zipFile.file.stat("file1").mode & 0777)
    assert_equal(0755, @zipFile.file.stat("dir1").mode & 0777)
    assert_equal(0755, @zipFile.file.stat("dir1").mode & 0777)
  end

  def test_dev
    assert_equal(0, @zipFile.file.stat("file1").dev)
  end

  def test_rdev
    assert_equal(0, @zipFile.file.stat("file1").rdev)
  end

  def test_rdev_major
    assert_equal(0, @zipFile.file.stat("file1").rdev_major)
  end

  def test_rdev_minor
    assert_equal(0, @zipFile.file.stat("file1").rdev_minor)
  end

  def test_nlink
    assert_equal(1, @zipFile.file.stat("file1").nlink)
  end

  def test_blksize
    assert_nil(@zipFile.file.stat("file1").blksize)
  end

end

class ZipFsFileMutatingTest < Test::Unit::TestCase
  TEST_ZIP = "zipWithDirs_copy.zip"
  def setup
    FileUtils.cp("data/zipWithDirs.zip", TEST_ZIP)
  end

  def teardown
  end
 
  def test_delete
    do_test_delete_or_unlink(:delete)
  end

  def test_unlink
    do_test_delete_or_unlink(:unlink)
  end
  
  def test_open_write
    ZipFile.open(TEST_ZIP) {
      |zf|

      zf.file.open("test_open_write_entry", "w") {
        |f|
        blockCalled = true
        f.write "This is what I'm writing"
      }
      assert_equal("This is what I'm writing",
                    zf.file.read("test_open_write_entry"))

      # Test with existing entry
      zf.file.open("file1", "wb") { #also check that 'b' option is ignored
        |f|
        blockCalled = true
        f.write "This is what I'm writing too"
      }
      assert_equal("This is what I'm writing too",
                    zf.file.read("file1"))
    }
  end

  def test_rename
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert_raise(Errno::ENOENT, "") { 
        zf.file.rename("NoSuchFile", "bimse")
      }
      zf.file.rename("file1", "newNameForFile1")
    }

    ZipFile.open(TEST_ZIP) {
      |zf|
      assert(! zf.file.exists?("file1"))
      assert(zf.file.exists?("newNameForFile1"))
    }
  end

  def do_test_delete_or_unlink(symbol)
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert(zf.file.exists?("dir2/dir21/dir221/file2221"))
      zf.file.send(symbol, "dir2/dir21/dir221/file2221")
      assert(! zf.file.exists?("dir2/dir21/dir221/file2221"))

      assert(zf.file.exists?("dir1/file11"))
      assert(zf.file.exists?("dir1/file12"))
      zf.file.send(symbol, "dir1/file11", "dir1/file12")
      assert(! zf.file.exists?("dir1/file11"))
      assert(! zf.file.exists?("dir1/file12"))

      assert_raise(Errno::ENOENT) { zf.file.send(symbol, "noSuchFile") }
      assert_raise(Errno::EISDIR) { zf.file.send(symbol, "dir1/dir11") }
      assert_raise(Errno::EISDIR) { zf.file.send(symbol, "dir1/dir11/") }
    }

    ZipFile.open(TEST_ZIP) {
      |zf|
      assert(! zf.file.exists?("dir2/dir21/dir221/file2221"))
      assert(! zf.file.exists?("dir1/file11"))
      assert(! zf.file.exists?("dir1/file12"))

      assert(zf.file.exists?("dir1/dir11"))
      assert(zf.file.exists?("dir1/dir11/"))
    }
  end

end

class ZipFsDirectoryTest < Test::Unit::TestCase
  TEST_ZIP = "zipWithDirs_copy.zip"

  def setup
    FileUtils.cp("data/zipWithDirs.zip", TEST_ZIP)
  end

  def test_delete
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert_raise(Errno::ENOENT, "No such file or directory - NoSuchFile.txt") {
        zf.dir.delete("NoSuchFile.txt")
      }
      assert_raise(Errno::EINVAL, "Invalid argument - file1") {
        zf.dir.delete("file1")
      }
      assert(zf.file.exists?("dir1"))
      zf.dir.delete("dir1")
      assert(! zf.file.exists?("dir1"))
    }
  end

  def test_mkdir
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert_raise(Errno::EEXIST, "File exists - dir1") { 
        zf.dir.mkdir("file1") 
      }
      assert_raise(Errno::EEXIST, "File exists - dir1") { 
        zf.dir.mkdir("dir1") 
      }
      assert(!zf.file.exists?("newDir"))
      zf.dir.mkdir("newDir")
      assert(zf.file.directory?("newDir"))
      assert(!zf.file.exists?("newDir2"))
      zf.dir.mkdir("newDir2", 3485)
      assert(zf.file.directory?("newDir2"))
    }
  end
  
  def test_pwd_chdir_entries
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert_equal("/", zf.dir.pwd)

      assert_raise(Errno::ENOENT, "No such file or directory - no such dir") {
        zf.dir.chdir "no such dir"
      }
      
      assert_raise(Errno::EINVAL, "Invalid argument - file1") {
        zf.dir.chdir "file1"
      }

      assert_equal(["dir1", "dir2", "file1"].sort, zf.dir.entries(".").sort)
      zf.dir.chdir "dir1"
      assert_equal("/dir1", zf.dir.pwd)
      assert_equal(["dir11", "file11", "file12"], zf.dir.entries(".").sort)
      
      zf.dir.chdir "../dir2/dir21"
      assert_equal("/dir2/dir21", zf.dir.pwd)
      assert_equal(["dir221"].sort, zf.dir.entries(".").sort)
    }
  end

  def test_foreach
    ZipFile.open(TEST_ZIP) {
      |zf|

      blockCalled = false
      assert_raise(Errno::ENOENT, "No such file or directory - noSuchDir") {
        zf.dir.foreach("noSuchDir") { |e| blockCalled = true }
      }
      assert(! blockCalled)

      assert_raise(Errno::ENOTDIR, "Not a directory - file1") {
        zf.dir.foreach("file1") { |e| blockCalled = true }
      }
      assert(! blockCalled)

      entries = []
      zf.dir.foreach(".") { |e| entries << e }
      assert_equal(["dir1", "dir2", "file1"].sort, entries.sort)

      entries = []
      zf.dir.foreach("dir1") { |e| entries << e }
      assert_equal(["dir11", "file11", "file12"], entries.sort)
    }
  end

  def test_chroot
    ZipFile.open(TEST_ZIP) {
      |zf|
      assert_raise(NotImplementedError) {
        zf.dir.chroot
      }
    }
  end

  # Globbing not supported yet
  #def test_glob
  #  # test alias []-operator too
  #  fail "implement test"
  #end

  def test_open_new
    ZipFile.open(TEST_ZIP) {
      |zf|

      assert_raise(Errno::ENOTDIR, "Not a directory - file1") {
        zf.dir.new("file1")
      }

      assert_raise(Errno::ENOENT, "No such file or directory - noSuchFile") {
        zf.dir.new("noSuchFile")
      }

      d = zf.dir.new(".")
      assert_equal(["file1", "dir1", "dir2"].sort, d.entries.sort)
      d.close

      zf.dir.open("dir1") {
        |dir|
        assert_equal(["dir11", "file11", "file12"].sort, dir.entries.sort)
      }
    }
  end

end

class ZipFsDirIteratorTest < Test::Unit::TestCase
  
  FILENAME_ARRAY = [ "f1", "f2", "f3", "f4", "f5", "f6"  ]

  def setup
    @dirIt = ZipFileSystem::ZipFsDirIterator.new(FILENAME_ARRAY)
  end

  def test_close
    @dirIt.close
    assert_raise(IOError, "closed directory") {
      @dirIt.each { |e| p e }
    }
    assert_raise(IOError, "closed directory") {
      @dirIt.read
    }
    assert_raise(IOError, "closed directory") {
      @dirIt.rewind
    }
    assert_raise(IOError, "closed directory") {
      @dirIt.seek(0)
    }
    assert_raise(IOError, "closed directory") {
      @dirIt.tell
    }
    
  end

  def test_each 
    # Tested through Enumerable.entries
    assert_equal(FILENAME_ARRAY, @dirIt.entries)
  end

  def test_read
    FILENAME_ARRAY.size.times {
      |i|
      assert_equal(FILENAME_ARRAY[i], @dirIt.read)
    }
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


# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
