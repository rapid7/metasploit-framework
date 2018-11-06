require 'minitest/autorun'
require 'readline'

require 'fileutils'
require "rbconfig"
require "support/filesystem_completion_helper"

class TestFilenameCompletionProc < Minitest::Test
  include FilesystemCompletionHelper

  def setup
    FileUtils.mkdir_p("#{SUB_SUB_DIR}")
    FileUtils.mkdir_p("#{SUB_DIR_WITH_SPACES}")
    @comp_test_dir = Dir.new COMP_TEST_DIR
    @sub_dir = Dir.new SUB_DIR
    @sub_sub_dir = Dir.new SUB_SUB_DIR
    @dir_with_spaces = Dir.new DIR_WITH_SPACES
    @sub_dir_with_spaces = Dir.new SUB_DIR_WITH_SPACES

    FileUtils.touch("#{@comp_test_dir.path}abc")
    FileUtils.touch("#{@comp_test_dir.path}aaa")
    FileUtils.touch("#{@sub_dir.path}abc")
    FileUtils.touch("#{@sub_dir.path}aaa")
    FileUtils.touch("#{@sub_sub_dir.path}aaa")
    FileUtils.touch("#{@dir_with_spaces.path}filename with spaces")
    FileUtils.touch("#{@sub_dir_with_spaces.path}another filename with spaces")

    # The previous Dir.new calls seem to cache the dir entries on Windows.
    @comp_test_dir = Dir.new COMP_TEST_DIR
    @sub_dir = Dir.new SUB_DIR
    @sub_sub_dir = Dir.new SUB_SUB_DIR
    @dir_with_spaces = Dir.new DIR_WITH_SPACES
    @sub_dir_with_spaces = Dir.new SUB_DIR_WITH_SPACES
    setup_filesystem_for_completion
  end

  def teardown
    teardown_filesystem_after_completion
  end

  def test_listing_files_in_cwd
    Dir.chdir(COMP_TEST_DIR) do
      entries = Dir.entries(".").select { |e| e[0,1] == "a" }
      assert_equal entries, Readline::FILENAME_COMPLETION_PROC.call("a")
    end
  end

  def test_list_files_in_sub_directories
    entries = @sub_dir.entries.select { |e| e[0,1] == "a" }
    entries.map! { |e| "#{@sub_dir.path}#{e}" }
    assert_equal entries, Readline::FILENAME_COMPLETION_PROC.call("#{@sub_dir.path}a")

    entries = @sub_sub_dir.entries - %w( . .. )
    entries.map! { |e| "#{@sub_sub_dir.path}#{e}" }
    assert_equal entries, Readline::FILENAME_COMPLETION_PROC.call("#{@sub_sub_dir.path}")
  end

  def test_list_files_and_directories_with_spaces
    entries = @comp_test_dir.entries.select { |e| e[0,1] == "d" }
    entries.map! { |e| @comp_test_dir.path + e }
    assert_equal entries, Readline::FILENAME_COMPLETION_PROC.call("#{@comp_test_dir.path}d")

    entries = @dir_with_spaces.entries - %w( . .. )
    entries.map! { |e| @dir_with_spaces.path + e }
    assert_equal entries, Readline::FILENAME_COMPLETION_PROC.call("#{@dir_with_spaces.path}")
  end

  def test_list_files_in_current_directory
    assert_equal((Dir.entries(".") - %w( . .. )).sort, Readline::FILENAME_COMPLETION_PROC.call("").sort)
  end

  def test_listing_files_with_no_read_access
    FileUtils.mkdir("test_no_access")
    FileUtils.touch("test_no_access/123")

    skip "chmod is noop in Windows" if windows?

    FileUtils.chmod(0333, "test_no_access")
    assert_nil Readline::FILENAME_COMPLETION_PROC.call("test_no_access/")
  ensure
    FileUtils.chmod(0775, "test_no_access")
    FileUtils.rm_r("test_no_access")
  end

  def windows?
    RbConfig::CONFIG["host_os"] =~ /mingw|mswin/
  end
end
