require 'sqlite3'
require 'minitest/autorun'

unless RUBY_VERSION >= "1.9"
  require 'iconv'
end

module SQLite3
  class TestCase < Minitest::Test
    alias :assert_not_equal :refute_equal
    alias :assert_not_nil   :refute_nil
    alias :assert_raise     :assert_raises

    def assert_nothing_raised
      yield
    end
  end
end
