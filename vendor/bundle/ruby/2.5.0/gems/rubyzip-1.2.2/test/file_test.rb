require 'test_helper'

class ZipFileTest < MiniTest::Test
  include CommonZipFileFixture
  include ZipEntryData

  OK_DELETE_FILE = 'test/data/generated/okToDelete.txt'
  OK_DELETE_MOVED_FILE = 'test/data/generated/okToDeleteMoved.txt'

  def teardown
    ::Zip.write_zip64_support = false
  end

  def test_create_from_scratch_to_buffer
    comment = 'a short comment'

    buffer = ::Zip::File.add_buffer do |zf|
      zf.get_output_stream('myFile') { |os| os.write 'myFile contains just this' }
      zf.mkdir('dir1')
      zf.comment = comment
    end

    ::File.open(EMPTY_FILENAME, 'wb') { |file| file.write buffer.string }

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal(comment, zfRead.comment)
    assert_equal(2, zfRead.entries.length)
  end

  def test_create_from_scratch
    comment = 'a short comment'

    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)
    zf.get_output_stream('myFile') { |os| os.write 'myFile contains just this' }
    zf.mkdir('dir1')
    zf.comment = comment
    zf.close

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal(comment, zfRead.comment)
    assert_equal(2, zfRead.entries.length)
  end

  def test_create_from_scratch_with_old_create_parameter
    comment = 'a short comment'

    zf = ::Zip::File.new(EMPTY_FILENAME, 1)
    zf.get_output_stream('myFile') { |os| os.write 'myFile contains just this' }
    zf.mkdir('dir1')
    zf.comment = comment
    zf.close

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal(comment, zfRead.comment)
    assert_equal(2, zfRead.entries.length)
  end

  def test_get_input_stream_stored_with_gpflag_bit3
    ::Zip::File.open('test/data/gpbit3stored.zip') do |zf|
      assert_equal("foo\n", zf.read("foo.txt"))
    end
  end

  def test_get_output_stream
    entryCount = nil
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      entryCount = zf.size
      zf.get_output_stream('newEntry.txt') do |os|
        os.write 'Putting stuff in newEntry.txt'
      end
      assert_equal(entryCount + 1, zf.size)
      assert_equal('Putting stuff in newEntry.txt', zf.read('newEntry.txt'))

      zf.get_output_stream(zf.get_entry('test/data/generated/empty.txt')) do |os|
        os.write 'Putting stuff in data/generated/empty.txt'
      end
      assert_equal(entryCount + 1, zf.size)
      assert_equal('Putting stuff in data/generated/empty.txt', zf.read('test/data/generated/empty.txt'))

      custom_entry_args = [TEST_COMMENT, TEST_EXTRA, TEST_COMPRESSED_SIZE, TEST_CRC, ::Zip::Entry::STORED, TEST_SIZE, TEST_TIME]
      zf.get_output_stream('entry_with_custom_args.txt', nil, *custom_entry_args) do |os|
        os.write 'Some data'
      end
      assert_equal(entryCount + 2, zf.size)
      entry = zf.get_entry('entry_with_custom_args.txt')
      assert_equal(custom_entry_args[0], entry.comment)
      assert_equal(custom_entry_args[2], entry.compressed_size)
      assert_equal(custom_entry_args[3], entry.crc)
      assert_equal(custom_entry_args[4], entry.compression_method)
      assert_equal(custom_entry_args[5], entry.size)
      assert_equal(custom_entry_args[6], entry.time)

      zf.get_output_stream('entry.bin') do |os|
        os.write(::File.open('test/data/generated/5entry.zip', 'rb').read)
      end
    end

    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(entryCount + 3, zf.size)
      assert_equal('Putting stuff in newEntry.txt', zf.read('newEntry.txt'))
      assert_equal('Putting stuff in data/generated/empty.txt', zf.read('test/data/generated/empty.txt'))
      assert_equal(File.open('test/data/generated/5entry.zip', 'rb').read, zf.read('entry.bin'))
    end
  end

  def test_open_buffer_with_stringio
    string_io = StringIO.new File.read('test/data/rubycode.zip')
    ::Zip::File.open_buffer string_io do |zf|
      assert zf.entries.map { |e| e.name }.include?('zippedruby1.rb')
    end
  end

  def test_close_buffer_with_stringio
    string_io = StringIO.new File.read('test/data/rubycode.zip')
    zf = ::Zip::File.open_buffer string_io
    assert(zf.close || true) # Poor man's refute_raises
  end

  def test_close_buffer_with_io
    f = File.open('test/data/rubycode.zip')
    zf = ::Zip::File.open_buffer f
    assert zf.close
    f.close
  end

  def test_open_buffer_without_block
    string_io = StringIO.new File.read('test/data/rubycode.zip')
    zf = ::Zip::File.open_buffer string_io
    assert zf.entries.map { |e| e.name }.include?('zippedruby1.rb')
  end

  def test_cleans_up_tempfiles_after_close
    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)
    zf.get_output_stream('myFile') do |os|
      @tempfile_path = os.path
      os.write 'myFile contains just this'
    end

    assert_equal(true, File.exist?(@tempfile_path))

    zf.close

    assert_equal(false, File.exist?(@tempfile_path))
  end

  def test_add
    srcFile = 'test/data/file2.txt'
    entryName = 'newEntryName.rb'
    assert(::File.exist?(srcFile))
    zf = ::Zip::File.new(EMPTY_FILENAME, ::Zip::File::CREATE)
    zf.add(entryName, srcFile)
    zf.close

    zfRead = ::Zip::File.new(EMPTY_FILENAME)
    assert_equal('', zfRead.comment)
    assert_equal(1, zfRead.entries.length)
    assert_equal(entryName, zfRead.entries.first.name)
    AssertEntry.assert_contents(srcFile,
                                zfRead.get_input_stream(entryName) { |zis| zis.read })
  end

  def test_recover_permissions_after_add_files_to_archive
    srcZip = TEST_ZIP.zip_name
    ::File.chmod(0o664, srcZip)
    srcFile = 'test/data/file2.txt'
    entryName = 'newEntryName.rb'
    assert_equal(::File.stat(srcZip).mode, 0o100664)
    assert(::File.exist?(srcZip))
    zf = ::Zip::File.new(srcZip, ::Zip::File::CREATE)
    zf.add(entryName, srcFile)
    zf.close
    assert_equal(::File.stat(srcZip).mode, 0o100664)
  end

  def test_add_existing_entry_name
    assert_raises(::Zip::EntryExistsError) do
      ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
        zf.add(zf.entries.first.name, 'test/data/file2.txt')
      end
    end
  end

  def test_add_existing_entry_name_replace
    gotCalled = false
    replacedEntry = nil
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      replacedEntry = zf.entries.first.name
      zf.add(replacedEntry, 'test/data/file2.txt') { gotCalled = true; true }
    end
    assert(gotCalled)
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_contains(zf, replacedEntry, 'test/data/file2.txt')
    end
  end

  def test_add_directory
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      zf.add(TestFiles::EMPTY_TEST_DIR, TestFiles::EMPTY_TEST_DIR)
    end
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      dirEntry = zf.entries.detect { |e| e.name == TestFiles::EMPTY_TEST_DIR + '/' }
      assert(dirEntry.directory?)
    end
  end

  def test_remove
    entryToRemove, *remainingEntries = TEST_ZIP.entry_names

    FileUtils.cp(TestZipFile::TEST_ZIP2.zip_name, TEST_ZIP.zip_name)

    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(zf.entries.map { |e| e.name }.include?(entryToRemove))
    zf.remove(entryToRemove)
    assert(!zf.entries.map { |e| e.name }.include?(entryToRemove))
    assert_equal(zf.entries.map { |x| x.name }.sort, remainingEntries.sort)
    zf.close

    zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(!zfRead.entries.map { |e| e.name }.include?(entryToRemove))
    assert_equal(zfRead.entries.map { |x| x.name }.sort, remainingEntries.sort)
    zfRead.close
  end

  def test_rename
    entryToRename, * = TEST_ZIP.entry_names

    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(zf.entries.map { |e| e.name }.include?(entryToRename))

    contents = zf.read(entryToRename)
    newName = 'changed entry name'
    assert(!zf.entries.map { |e| e.name }.include?(newName))

    zf.rename(entryToRename, newName)
    assert(zf.entries.map { |e| e.name }.include?(newName))

    assert_equal(contents, zf.read(newName))

    zf.close

    zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(zfRead.entries.map { |e| e.name }.include?(newName))
    assert_equal(contents, zfRead.read(newName))
    zfRead.close
  end

  def test_rename_with_each
    zf_name = 'test_rename_zip.zip'
    ::File.unlink(zf_name) if ::File.exist?(zf_name)
    arr = []
    arr_renamed = []
    ::Zip::File.open(zf_name, ::Zip::File::CREATE) do |zf|
      zf.mkdir('test')
      arr << 'test/'
      arr_renamed << 'Ztest/'
      %w[a b c d].each do |f|
        zf.get_output_stream("test/#{f}") { |file| file.puts 'aaaa' }
        arr << "test/#{f}"
        arr_renamed << "Ztest/#{f}"
      end
    end
    zf = ::Zip::File.open(zf_name)
    assert_equal(zf.entries.map(&:name), arr)
    zf.close
    Zip::File.open(zf_name, 'wb') do |z|
      z.each do |f|
        z.rename(f, "Z#{f.name}")
      end
    end
    zf = ::Zip::File.open(zf_name)
    assert_equal(zf.entries.map(&:name), arr_renamed)
    zf.close
    ::File.unlink(zf_name) if ::File.exist?(zf_name)
  end

  def test_rename_to_existing_entry
    oldEntries = nil
    ::Zip::File.open(TEST_ZIP.zip_name) { |zf| oldEntries = zf.entries }

    assert_raises(::Zip::EntryExistsError) do
      ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
        zf.rename(zf.entries[0], zf.entries[1].name)
      end
    end

    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(oldEntries.sort.map { |e| e.name }, zf.entries.sort.map { |e| e.name })
    end
  end

  def test_rename_to_existing_entry_overwrite
    oldEntries = nil
    ::Zip::File.open(TEST_ZIP.zip_name) { |zf| oldEntries = zf.entries }

    gotCalled = false
    renamedEntryName = nil
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      renamedEntryName = zf.entries[0].name
      zf.rename(zf.entries[0], zf.entries[1].name) { gotCalled = true; true }
    end

    assert(gotCalled)
    oldEntries.delete_if { |e| e.name == renamedEntryName }
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(oldEntries.sort.map { |e| e.name },
                   zf.entries.sort.map { |e| e.name })
    end
  end

  def test_rename_non_entry
    nonEntry = 'bogusEntry'
    target_entry = 'target_entryName'
    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(!zf.entries.include?(nonEntry))
    assert_raises(Errno::ENOENT) { zf.rename(nonEntry, target_entry) }
    zf.commit
    assert(!zf.entries.include?(target_entry))
  ensure
    zf.close
  end

  def test_rename_entry_to_existing_entry
    entry1, entry2, * = TEST_ZIP.entry_names
    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    assert_raises(::Zip::EntryExistsError) { zf.rename(entry1, entry2) }
  ensure
    zf.close
  end

  def test_replace
    entryToReplace = TEST_ZIP.entry_names[2]
    newEntrySrcFilename = 'test/data/file2.txt'
    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    zf.replace(entryToReplace, newEntrySrcFilename)

    zf.close
    zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
    AssertEntry.assert_contents(newEntrySrcFilename,
                                zfRead.get_input_stream(entryToReplace) { |is| is.read })
    AssertEntry.assert_contents(TEST_ZIP.entry_names[0],
                                zfRead.get_input_stream(TEST_ZIP.entry_names[0]) { |is| is.read })
    AssertEntry.assert_contents(TEST_ZIP.entry_names[1],
                                zfRead.get_input_stream(TEST_ZIP.entry_names[1]) { |is| is.read })
    AssertEntry.assert_contents(TEST_ZIP.entry_names[3],
                                zfRead.get_input_stream(TEST_ZIP.entry_names[3]) { |is| is.read })
    zfRead.close
  end

  def test_replace_non_entry
    entryToReplace = 'nonExistingEntryname'
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_raises(Errno::ENOENT) { zf.replace(entryToReplace, 'test/data/file2.txt') }
    end
  end

  def test_commit
    newName = 'renamedFirst'
    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    oldName = zf.entries.first
    zf.rename(oldName, newName)
    zf.commit

    zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(zfRead.entries.detect { |e| e.name == newName } != nil)
    assert(zfRead.entries.detect { |e| e.name == oldName }.nil?)
    zfRead.close

    zf.close
    res = system("unzip -tqq #{TEST_ZIP.zip_name}")
    assert_equal(res, true)
  end

  def test_double_commit(filename = 'test/data/generated/double_commit_test.zip')
    ::FileUtils.touch('test/data/generated/test_double_commit1.txt')
    ::FileUtils.touch('test/data/generated/test_double_commit2.txt')
    zf = ::Zip::File.open(filename, ::Zip::File::CREATE)
    zf.add('test1.txt', 'test/data/generated/test_double_commit1.txt')
    zf.commit
    zf.add('test2.txt', 'test/data/generated/test_double_commit2.txt')
    zf.commit
    zf.close
    zf2 = ::Zip::File.open(filename)
    assert(zf2.entries.detect { |e| e.name == 'test1.txt' } != nil)
    assert(zf2.entries.detect { |e| e.name == 'test2.txt' } != nil)
    res = system("unzip -tqq #{filename}")
    assert_equal(res, true)
  end

  def test_double_commit_zip64
    ::Zip.write_zip64_support = true
    test_double_commit('test/data/generated/double_commit_test64.zip')
  end

  def test_write_buffer
    newName = 'renamedFirst'
    zf = ::Zip::File.new(TEST_ZIP.zip_name)
    oldName = zf.entries.first
    zf.rename(oldName, newName)
    io = ::StringIO.new('')
    buffer = zf.write_buffer(io)
    File.open(TEST_ZIP.zip_name, 'wb') { |f| f.write buffer.string }
    zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
    assert(zfRead.entries.detect { |e| e.name == newName } != nil)
    assert(zfRead.entries.detect { |e| e.name == oldName }.nil?)
    zfRead.close

    zf.close
  end

  # This test tests that after commit, you
  # can delete the file you used to add the entry to the zip file
  # with
  def test_commit_use_zip_entry
    FileUtils.cp(TestFiles::RANDOM_ASCII_FILE1, OK_DELETE_FILE)
    zf = ::Zip::File.open(TEST_ZIP.zip_name)
    zf.add('okToDelete.txt', OK_DELETE_FILE)
    assert_contains(zf, 'okToDelete.txt')
    zf.commit
    File.rename(OK_DELETE_FILE, OK_DELETE_MOVED_FILE)
    assert_contains(zf, 'okToDelete.txt', OK_DELETE_MOVED_FILE)
  end

  #  def test_close
  #    zf = ZipFile.new(TEST_ZIP.zip_name)
  #    zf.close
  #    assert_raises(IOError) {
  #      zf.extract(TEST_ZIP.entry_names.first, "hullubullu")
  #    }
  #  end

  def test_compound1
    renamedName = 'renamedName'
    filename_to_remove = ''
    begin
      zf = ::Zip::File.new(TEST_ZIP.zip_name)
      originalEntries = zf.entries.dup

      assert_not_contains(zf, TestFiles::RANDOM_ASCII_FILE1)
      zf.add(TestFiles::RANDOM_ASCII_FILE1,
             TestFiles::RANDOM_ASCII_FILE1)
      assert_contains(zf, TestFiles::RANDOM_ASCII_FILE1)

      entry_to_rename = zf.entries.find { |entry| entry.name.match('longAscii') }
      zf.rename(entry_to_rename, renamedName)
      assert_contains(zf, renamedName)

      TestFiles::BINARY_TEST_FILES.each do |filename|
        zf.add(filename, filename)
        assert_contains(zf, filename)
      end

      assert_contains(zf, originalEntries.last.to_s)
      filename_to_remove = originalEntries.map(&:to_s).find { |name| name.match('longBinary') }
      zf.remove(filename_to_remove)
      assert_not_contains(zf, filename_to_remove)
    ensure
      zf.close
    end
    begin
      zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
      assert_contains(zfRead, TestFiles::RANDOM_ASCII_FILE1)
      assert_contains(zfRead, renamedName)
      TestFiles::BINARY_TEST_FILES.each do |filename|
        assert_contains(zfRead, filename)
      end
      assert_not_contains(zfRead, filename_to_remove)
    ensure
      zfRead.close
    end
  end

  def test_compound2
    begin
      zf = ::Zip::File.new(TEST_ZIP.zip_name)
      originalEntries = zf.entries.dup

      originalEntries.each do |entry|
        zf.remove(entry)
        assert_not_contains(zf, entry)
      end
      assert(zf.entries.empty?)

      TestFiles::ASCII_TEST_FILES.each do |filename|
        zf.add(filename, filename)
        assert_contains(zf, filename)
      end
      assert_equal(zf.entries.sort.map { |e| e.name }, TestFiles::ASCII_TEST_FILES)

      zf.rename(TestFiles::ASCII_TEST_FILES[0], 'newName')
      assert_not_contains(zf, TestFiles::ASCII_TEST_FILES[0])
      assert_contains(zf, 'newName')
    ensure
      zf.close
    end
    begin
      zfRead = ::Zip::File.new(TEST_ZIP.zip_name)
      asciiTestFiles = TestFiles::ASCII_TEST_FILES.dup
      asciiTestFiles.shift
      asciiTestFiles.each do |filename|
        assert_contains(zf, filename)
      end

      assert_contains(zf, 'newName')
    ensure
      zfRead.close
    end
  end

  def test_change_comment
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      zf.comment = 'my changed comment'
    end
    zfRead = ::Zip::File.open(TEST_ZIP.zip_name)
    assert_equal('my changed comment', zfRead.comment)
  end

  def test_preserve_file_order
    entryNames = nil
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      entryNames = zf.entries.map { |e| e.to_s }
      zf.get_output_stream('a.txt') { |os| os.write 'this is a.txt' }
      zf.get_output_stream('z.txt') { |os| os.write 'this is z.txt' }
      zf.get_output_stream('k.txt') { |os| os.write 'this is k.txt' }
      entryNames << 'a.txt' << 'z.txt' << 'k.txt'
    end

    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(entryNames, zf.entries.map { |e| e.to_s })
      entries = zf.entries.sort_by { |e| e.name }.reverse
      entries.each do |e|
        zf.remove e
        zf.get_output_stream(e) { |os| os.write 'foo' }
      end
      entryNames = entries.map { |e| e.to_s }
    end
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(entryNames, zf.entries.map { |e| e.to_s })
    end
  end

  def test_streaming
    fname = ::File.join(::File.expand_path(::File.dirname(__FILE__)), '../README.md')
    zname = 'test/data/generated/README.zip'
    Zip::File.open(zname, Zip::File::CREATE) do |zipfile|
      zipfile.get_output_stream(File.basename(fname)) do |f|
        f.puts File.read(fname)
      end
    end

    data = nil
    File.open(zname, 'rb') do |f|
      Zip::File.open_buffer(f) do |zipfile|
        zipfile.each do |entry|
          next unless entry.name =~ /README.md/
          data = zipfile.read(entry)
        end
      end
    end
    assert data
    assert data =~ /Simonov/
  end

  def test_nonexistant_zip
    assert_raises(::Zip::Error) do
      ::Zip::File.open('fake.zip')
    end
  end

  def test_empty_zip
    assert_raises(::Zip::Error) do
      ::Zip::File.open(TestFiles::NULL_FILE)
    end
  end

  def test_odd_extra_field
    entry_count = 0
    File.open 'test/data/oddExtraField.zip', 'rb' do |zip_io|
      Zip::File.open_buffer zip_io.read do |zip|
        zip.each do |_zip_entry|
          entry_count += 1
        end
      end
    end
    assert_equal 13, entry_count
  end

  def test_open_xls_does_not_raise_type_error
    ::Zip::File.open('test/data/test.xls')
  end

  private

  def assert_contains(zf, entryName, filename = entryName)
    assert(zf.entries.detect { |e| e.name == entryName } != nil, "entry #{entryName} not in #{zf.entries.join(', ')} in zip file #{zf}")
    assert_entry_contents(zf, entryName, filename) if File.exist?(filename)
  end

  def assert_not_contains(zf, entryName)
    assert(zf.entries.detect { |e| e.name == entryName }.nil?, "entry #{entryName} in #{zf.entries.join(', ')} in zip file #{zf}")
  end
end
