require 'test_helper'
require 'tempfile'

class RedcarpetBinTest < Redcarpet::TestCase
  def setup
    @fixture_file = Tempfile.new('bin')
    @fixture_path = @fixture_file.path

    @fixture_file.write "A ==simple== fixture file -- with " \
                        "a [link](https://github.com)."
    @fixture_file.rewind
  end

  def teardown
    @fixture_file.unlink
  end

  def test_vanilla_bin
    run_bin(@fixture_path)

    expected = "<p>A ==simple== fixture file -- with " \
               "a <a href=\"https://github.com\">link</a>.</p>\n"

    assert_equal expected, @output
  end

  def test_enabling_a_parse_option
    run_bin("--parse", "highlight", @fixture_path)

    assert_output "<mark>"
    refute_output "=="
  end

  def test_enabling_a_render_option
    run_bin("--render", "no-links", @fixture_path)

    assert_output "[link]"
    refute_output "</a>"
  end

  def test_enabling_smarty_pants
    run_bin("--smarty", @fixture_path)

    assert_output "&ndash"
    refute_output "--"
  end

  def test_version_option
    run_bin("--version")
    assert_output "Redcarpet #{Redcarpet::VERSION}"
  end

  def test_legacy_option_parsing
    run_bin("--parse-highlight", "--render-no-links", @fixture_path)

    assert_output "<mark>"
    refute_output "=="

    assert_output "[link]"
    refute_output "</a>"
  end

  private

  def run_bin(*args)
    bin_path = File.expand_path('../../bin/redcarpet', __FILE__)
    ruby = "ruby " if RUBY_PLATFORM =~ /mswin|mingw/
    IO.popen("#{ruby}#{bin_path} #{args.join(" ")}") do |stream|
      @output = stream.read
    end
  end

  def assert_output(pattern)
    assert_match pattern, @output
  end

  def refute_output(pattern)
    refute_match Regexp.new(pattern), @output
  end
end
