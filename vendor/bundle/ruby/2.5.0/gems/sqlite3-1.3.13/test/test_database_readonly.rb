require 'helper'

module SQLite3
  class TestDatabaseReadonly < SQLite3::TestCase
    def setup
      File.unlink 'test-readonly.db' if File.exist?('test-readonly.db')
      @db = SQLite3::Database.new('test-readonly.db')
      @db.execute("CREATE TABLE foos (id integer)")
      @db.close
    end

    def teardown
      @db.close unless @db.closed?
      File.unlink 'test-readonly.db' if File.exist?('test-readonly.db')
    end

    def test_open_readonly_database
      @db = SQLite3::Database.new('test-readonly.db', :readonly => true)
      assert @db.readonly?
    end

    def test_open_readonly_not_exists_database
      File.unlink 'test-readonly.db'
      assert_raise(SQLite3::CantOpenException) do
        @db = SQLite3::Database.new('test-readonly.db', :readonly => true)
      end
    end

    def test_insert_readonly_database
      @db = SQLite3::Database.new('test-readonly.db', :readonly => true)
      assert_raise(SQLite3::ReadOnlyException) do
        @db.execute("INSERT INTO foos (id) VALUES (12)")
      end
    end
  end
end
