require 'test_helper'

class FilePermissionsTest < MiniTest::Test
  ZIPNAME = File.join(File.dirname(__FILE__), 'umask.zip')
  FILENAME = File.join(File.dirname(__FILE__), 'umask.txt')

  def teardown
    ::File.unlink(ZIPNAME)
    ::File.unlink(FILENAME)
  end

  def test_current_umask
    create_files
    assert_matching_permissions FILENAME, ZIPNAME
  end

  def test_umask_000
    set_umask(0o000) do
      create_files
    end

    assert_matching_permissions FILENAME, ZIPNAME
  end

  def test_umask_066
    set_umask(0o066) do
      create_files
    end

    assert_matching_permissions FILENAME, ZIPNAME
  end

  def test_umask_027
    set_umask(0o027) do
      create_files
    end

    assert_matching_permissions FILENAME, ZIPNAME
  end

  def assert_matching_permissions(expected_file, actual_file)
    assert_equal(
      ::File.stat(expected_file).mode.to_s(8).rjust(4, '0'),
      ::File.stat(actual_file).mode.to_s(8).rjust(4, '0')
    )
  end

  def create_files
    ::Zip::File.open(ZIPNAME, ::Zip::File::CREATE) do |zip|
      zip.comment = 'test'
    end

    ::File.open(FILENAME, 'w') do |file|
      file << 'test'
    end
  end

  # If anything goes wrong, make sure the umask is restored.
  def set_umask(umask)
    saved_umask = ::File.umask(umask)
    yield
  ensure
    ::File.umask(saved_umask)
  end
end
