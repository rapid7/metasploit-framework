require 'rubygems'
require 'minitest/autorun'
require 'minitest/benchmark' if ENV['BENCHMARK']

require 'fileutils'
require 'pp'
require 'tempfile'
require 'tmpdir'
require 'stringio'

require 'rdoc'

##
# RDoc::TestCase is an abstract TestCase to provide common setup and teardown
# across all RDoc tests.  The test case uses minitest, so all the assertions
# of minitest may be used.
#
# The testcase provides the following:
#
# * A reset code-object tree
# * A reset markup preprocessor (RDoc::Markup::PreProcess)
# * The <code>@RM</code> alias of RDoc::Markup (for less typing)
# * <code>@pwd</code> containing the current working directory
# * FileUtils, pp, Tempfile, Dir.tmpdir and StringIO

class RDoc::TestCase < MiniTest::Unit::TestCase

  ##
  # Abstract test-case setup

  def setup
    super

    @top_level = nil

    @RM = RDoc::Markup

    RDoc::RDoc.reset
    RDoc::Markup::PreProcess.reset

    @pwd = Dir.pwd
  end

  ##
  # Creates an RDoc::Comment with +text+ which was defined on +top_level+.
  # By default the comment has the 'rdoc' format.

  def comment text, top_level = @top_level
    RDoc::Comment.new text, top_level
  end

  ##
  # Creates a temporary directory changes the current directory to it for the
  # duration of the block.
  #
  # Depends upon Dir.mktmpdir

  def temp_dir
    skip "No Dir::mktmpdir, upgrade your ruby" unless Dir.respond_to? :mktmpdir

    Dir.mktmpdir do |temp_dir|
      Dir.chdir temp_dir do
        yield temp_dir
      end
    end
  end

end

# This hack allows autoload to work when Dir.pwd is changed for Ruby 1.8 since
# -I paths are not expanded.
$LOAD_PATH.each do |load_path|
  break if load_path[0] == ?/
  load_path.replace File.expand_path load_path
end if RUBY_VERSION < '1.9'

