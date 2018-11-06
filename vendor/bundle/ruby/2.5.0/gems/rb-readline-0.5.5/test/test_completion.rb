require "minitest/autorun"
require "readline"

require 'timeout'
require "support/filesystem_completion_helper"

class TestCompletion < Minitest::Test
  include RbReadline
  include FilesystemCompletionHelper

  def filename_quoting_function(filename, mtype, quote_char)
    quoted_filename = filename.dup
    @rl_filename_quote_characters.split("").each do |c|
      quoted_filename.gsub!(c, "\\#{c}")
    end
    quoted_filename
  end

  def filename_dequoting_function(filename, quote_char = "\\")
    filename.delete quote_char
  end

  def setup
    @rl_completion_word_break_hook, @rl_char_is_quoted_p = nil
    @rl_basic_quote_characters, @rl_special_prefixes = nil
    @rl_completer_word_break_characters = Readline.basic_word_break_characters
    @rl_completer_quote_characters = "\\"
    @rl_completion_quote_character = "\\"
    @rl_filename_quote_characters = " "
    @rl_byte_oriented = true
    @rl_filename_quoting_desired = true
    @rl_filename_completion_desired = true
    @rl_complete_with_tilde_expansion = true
    @_rl_match_hidden_files = false
    @rl_completion_found_quote = false
    @_rl_completion_case_fold = false
    @directory = nil

    @rl_filename_quoting_function = :filename_quoting_function
    @rl_filename_dequoting_function = :filename_dequoting_function
    @rl_directory_completion_hook = nil

    setup_filesystem_for_completion
  end

  def teardown
    teardown_filesystem_after_completion
  end

  def set_line_buffer(text)
    @rl_line_buffer = text
    @rl_point = @rl_line_buffer.size
    @rl_line_buffer << 0.chr
  end

  def test__find_completion_word_doesnt_hang_on_completer_quote_character
    set_line_buffer "#{@dir_with_spaces.path}filename\\ w"

    Timeout::timeout(3) do
      assert_equal([ "\000", true, "\000" ], _rl_find_completion_word)
    end
  end

  def test__find_completion_word_without_quote_characters
    set_line_buffer "#{@comp_test_dir.path}a"
    assert_equal([ "\000", false, "\000" ], _rl_find_completion_word)
  end

  def test_make_quoted_replacement_calls_filename_quoting_function
    assert_equal "dir/with\\ space", make_quoted_replacement("dir/with space", RbReadline::SINGLE_MATCH, 0.chr)
  end

  def test_rl_filname_completion_function_calls_dequoting_function
    @rl_completion_found_quote = true
    dir = filename_quoting_function(@dir_with_spaces.path, nil, 0.chr)

    # rl_filename_completion_function is called with an increasing state in
    # order to iterate through directory entries.

    entries = [ "#{@dir_with_spaces.path}sub dir with spaces", "#{@dir_with_spaces.path}filename with spaces" ]

    assert entries.include?(rl_filename_completion_function(dir, 0))
    assert entries.include?(rl_filename_completion_function(dir, 1))
    assert_nil rl_filename_completion_function(dir, 2)
  ensure
    @rl_completion_found_quote = false
  end

  def test_completing_path_starting_dot_slash
    assert_equal "./#{COMP_TEST_DIR.chop}", rl_filename_completion_function("./#{COMP_TEST_DIR.chop}", 0)
  end

  def test_completing_non_existant_directory
    assert_nil rl_filename_completion_function("/this/dir/does/not/exist", 0)
  end

  def test_completing_a_file_as_a_directory
    assert_nil rl_filename_completion_function("#{File.expand_path(__FILE__)}/", 0)
  end
end
