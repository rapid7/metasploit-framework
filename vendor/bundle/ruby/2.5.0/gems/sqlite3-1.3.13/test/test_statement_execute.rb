require 'helper'

module SQLite3
  class TestStatementExecute < SQLite3::TestCase
    def setup
      @db   = SQLite3::Database.new(':memory:')
      @db.execute_batch(
        "CREATE TABLE items (id integer PRIMARY KEY, number integer)")
    end

    def test_execute_insert
      ps = @db.prepare("INSERT INTO items (number) VALUES (:n)")
      ps.execute('n'=>10)
      assert_equal 1, @db.get_first_value("SELECT count(*) FROM items")
      ps.close
    end

    def test_execute_update
      @db.execute("INSERT INTO items (number) VALUES (?)", [10])

      ps = @db.prepare("UPDATE items SET number = :new WHERE number = :old")
      ps.execute('old'=>10, 'new'=>20)
      assert_equal 20, @db.get_first_value("SELECT number FROM items")
      ps.close
    end

    def test_execute_delete
      @db.execute("INSERT INTO items (number) VALUES (?)", [20])
      ps = @db.prepare("DELETE FROM items WHERE number = :n")
      ps.execute('n' => 20)
      assert_equal 0, @db.get_first_value("SELECT count(*) FROM items")
      ps.close
    end
  end
end
