require 'helper'

module SQLite3
  class TestSQLite3 < SQLite3::TestCase
    def test_libversion
      assert_not_nil SQLite3.libversion
    end

    def test_threadsafe
      assert_not_nil SQLite3.threadsafe
    end

    def test_threadsafe?
      if SQLite3.threadsafe > 0
        assert SQLite3.threadsafe?
      else
        refute SQLite3.threadsafe?
      end
    end
  end
end
