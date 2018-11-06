class PathTraversalTest < MiniTest::Test
  TEST_FILE_ROOT = File.absolute_path('test/data/path_traversal')

  def setup
    # With apologies to anyone using these files... but they are the files in
    # the sample zips, so we don't have much choice here.
    FileUtils.rm_f '/tmp/moo'
    FileUtils.rm_f '/tmp/file.txt'
  end

  def extract_path_traversal_zip(name)
    Zip::File.open(File.join(TEST_FILE_ROOT, name)) do |zip_file|
      zip_file.each do |entry|
        entry.extract
      end
    end
  end

  def in_tmpdir
    Dir.mktmpdir do |tmp|
      test_path = File.join(tmp, 'test')
      Dir.mkdir test_path
      Dir.chdir test_path do
        yield test_path
      end
    end
  end

  def test_leading_slash
    in_tmpdir do
      extract_path_traversal_zip 'jwilk/absolute1.zip'
      refute File.exist?('/tmp/moo')
    end
  end

  def test_multiple_leading_slashes
    in_tmpdir do
      extract_path_traversal_zip 'jwilk/absolute2.zip'
      refute File.exist?('/tmp/moo')
    end
  end

  def test_leading_dot_dot
    in_tmpdir do
      extract_path_traversal_zip 'jwilk/relative0.zip'
      refute File.exist?('../moo')
    end
  end

  def test_non_leading_dot_dot_with_existing_folder
    in_tmpdir do
      extract_path_traversal_zip 'relative1.zip'
      assert Dir.exist?('tmp')
      refute File.exist?('../moo')
    end
  end

  def test_non_leading_dot_dot_without_existing_folder
    in_tmpdir do
      extract_path_traversal_zip 'jwilk/relative2.zip'
      refute File.exist?('../moo')
    end
  end

  def test_file_symlink
    in_tmpdir do
      extract_path_traversal_zip 'jwilk/symlink.zip'
      assert File.exist?('moo')
      refute File.exist?('/tmp/moo')
    end
  end

  def test_directory_symlink
    in_tmpdir do
      # Can't create tmp/moo, because the tmp symlink is skipped.
      assert_raises Errno::ENOENT do
        extract_path_traversal_zip 'jwilk/dirsymlink.zip'
      end
      refute File.exist?('/tmp/moo')
    end
  end

  def test_two_directory_symlinks_a
    in_tmpdir do
      # Can't create par/moo because the symlinks are skipped.
      assert_raises Errno::ENOENT do
        extract_path_traversal_zip 'jwilk/dirsymlink2a.zip'
      end
      refute File.exist?('cur')
      refute File.exist?('par')
      refute File.exist?('par/moo')
    end
  end

  def test_two_directory_symlinks_b
    in_tmpdir do
      # Can't create par/moo, because the symlinks are skipped.
      assert_raises Errno::ENOENT do
        extract_path_traversal_zip 'jwilk/dirsymlink2b.zip'
      end
      refute File.exist?('cur')
      refute File.exist?('../moo')
    end
  end

  def test_entry_name_with_absolute_path_does_not_extract
    in_tmpdir do
      extract_path_traversal_zip 'tuzovakaoff/absolutepath.zip'
      refute File.exist?('/tmp/file.txt')
    end
  end

  def test_entry_name_with_absolute_path_extract_when_given_different_path
    in_tmpdir do |test_path|
      zip_path = File.join(TEST_FILE_ROOT, 'tuzovakaoff/absolutepath.zip')
      Zip::File.open(zip_path) do |zip_file|
        zip_file.each do |entry|
          entry.extract(File.join(test_path, entry.name))
        end
      end
      refute File.exist?('/tmp/file.txt')
    end
  end

  def test_entry_name_with_relative_symlink
    in_tmpdir do
      # Doesn't create the symlink path, so can't create path/file.txt.
      assert_raises Errno::ENOENT do
        extract_path_traversal_zip 'tuzovakaoff/symlink.zip'
      end
      refute File.exist?('/tmp/file.txt')
    end
  end
end
