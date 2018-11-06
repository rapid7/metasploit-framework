require "fileutils"

module FilesystemCompletionHelper
  SEP = File::SEPARATOR
  COMP_TEST_DIR = "comp_test#{SEP}"
  SUB_DIR = "#{COMP_TEST_DIR}a_sub_dir#{SEP}"
  SUB_SUB_DIR = "#{SUB_DIR}another_sub_dir#{SEP}"
  DIR_WITH_SPACES = "#{COMP_TEST_DIR}dir with spaces#{SEP}"
  SUB_DIR_WITH_SPACES = "#{DIR_WITH_SPACES}sub dir with spaces#{SEP}"

  # This creates:
  #
  #   comp_test/
  #     abc
  #     aaa
  #     a_sub_dir/
  #       abc
  #       aaa
  #       another_sub_dir/
  #         aaa
  #     dir with spaces/
  #       filename with spaces
  #       sub dir with spaces/
  #         another filename with spaces
  def setup_filesystem_for_completion
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
    @sub_dir_with_spaces = Dir.new SUB_DIR_WITH_SPACES
    @dir_with_spaces = Dir.new DIR_WITH_SPACES
  end

  def teardown_filesystem_after_completion
    FileUtils.rm_r(COMP_TEST_DIR)
  end
end
