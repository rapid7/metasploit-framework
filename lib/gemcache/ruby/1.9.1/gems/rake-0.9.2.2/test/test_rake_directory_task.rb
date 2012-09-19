require File.expand_path('../helper', __FILE__)
require 'fileutils'

class TestRakeDirectoryTask < Rake::TestCase
  include Rake

  def test_directory
    desc "DESC"

    directory "a/b/c"

    assert_equal FileCreationTask, Task["a"].class
    assert_equal FileCreationTask, Task["a/b"].class
    assert_equal FileCreationTask, Task["a/b/c"].class

    assert_nil             Task["a"].comment
    assert_nil             Task["a/b"].comment
    assert_equal "DESC",   Task["a/b/c"].comment

    verbose(false) {
      Task['a/b'].invoke
    }

    assert File.exist?("a/b")
    refute File.exist?("a/b/c")
  end

  if Rake::Win32.windows?
    def test_directory_win32
      desc "WIN32 DESC"
      directory 'c:/a/b/c'
      assert_equal FileTask, Task['c:'].class
      assert_equal FileCreationTask, Task['c:/a'].class
      assert_equal FileCreationTask, Task['c:/a/b'].class
      assert_equal FileCreationTask, Task['c:/a/b/c'].class
      assert_nil             Task['c:/'].comment
      assert_equal "WIN32 DESC",   Task['c:/a/b/c'].comment
      assert_nil             Task['c:/a/b'].comment
      verbose(false) {
        Task['c:/a/b'].invoke
      }
      assert File.exist?('c:/a/b')
      refute File.exist?('c:/a/b/c')
    end
  end
end
