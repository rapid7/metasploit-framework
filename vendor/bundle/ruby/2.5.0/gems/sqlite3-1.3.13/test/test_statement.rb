require 'helper'

module SQLite3
  class TestStatement < SQLite3::TestCase
    def setup
      @db   = SQLite3::Database.new(':memory:')
      @stmt = SQLite3::Statement.new(@db, "select 'foo'")
    end

    def test_double_close_does_not_segv
      @db.execute 'CREATE TABLE "things" ("number" float NOT NULL)'

      stmt = @db.prepare 'INSERT INTO things (number) VALUES (?)'
      assert_raises(SQLite3::ConstraintException) { stmt.execute(nil) }

      stmt.close

      assert_raises(SQLite3::Exception) { stmt.close }
    end

    def test_raises_type_error
      assert_raises(TypeError) do
        SQLite3::Statement.new( @db, nil )
      end
    end

    def test_insert_duplicate_records
      @db.execute 'CREATE TABLE "things" ("name" varchar(20) CONSTRAINT "index_things_on_name" UNIQUE)'
      stmt = @db.prepare("INSERT INTO things(name) VALUES(?)")
      stmt.execute('ruby')

      exception = assert_raises(SQLite3::ConstraintException) { stmt.execute('ruby') }
      # SQLite 3.8.2 returns new error message:
      #   UNIQUE constraint failed: *table_name*.*column_name*
      # Older versions of SQLite return:
      #   column *column_name* is not unique
      assert_match(/(column(s)? .* (is|are) not unique|UNIQUE constraint failed: .*)/, exception.message)
    end

    ###
    # This method may not exist depending on how sqlite3 was compiled
    def test_database_name
      @db.execute('create table foo(text BLOB)')
      @db.execute('insert into foo(text) values (?)',SQLite3::Blob.new('hello'))
      stmt = @db.prepare('select text from foo')
      if stmt.respond_to?(:database_name)
        assert_equal 'main', stmt.database_name(0)
      end
    end

    def test_prepare_blob
      @db.execute('create table foo(text BLOB)')
      stmt = @db.prepare('insert into foo(text) values (?)')
      stmt.bind_param(1, SQLite3::Blob.new('hello'))
      stmt.step
      stmt.close
    end

    def test_select_blob
      @db.execute('create table foo(text BLOB)')
      @db.execute('insert into foo(text) values (?)',SQLite3::Blob.new('hello'))
      assert_equal 'hello', @db.execute('select * from foo').first.first
    end

    def test_new
      assert @stmt
    end

    def test_new_closed_handle
      @db = SQLite3::Database.new(':memory:')
      @db.close
      assert_raises(ArgumentError) do
        SQLite3::Statement.new(@db, 'select "foo"')
      end
    end

    def test_new_with_remainder
      stmt = SQLite3::Statement.new(@db, "select 'foo';bar")
      assert_equal 'bar', stmt.remainder
    end

    def test_empty_remainder
      assert_equal '', @stmt.remainder
    end

    def test_close
      @stmt.close
      assert @stmt.closed?
    end

    def test_double_close
      @stmt.close
      assert_raises(SQLite3::Exception) do
        @stmt.close
      end
    end

    def test_bind_param_string
      stmt = SQLite3::Statement.new(@db, "select ?")
      stmt.bind_param(1, "hello")
      result = nil
      stmt.each { |x| result = x }
      assert_equal ['hello'], result
    end

    def test_bind_param_int
      stmt = SQLite3::Statement.new(@db, "select ?")
      stmt.bind_param(1, 10)
      result = nil
      stmt.each { |x| result = x }
      assert_equal [10], result
    end

    def test_bind_nil
      stmt = SQLite3::Statement.new(@db, "select ?")
      stmt.bind_param(1, nil)
      result = nil
      stmt.each { |x| result = x }
      assert_equal [nil], result
    end

    def test_bind_blobs
    end

    def test_bind_64
      stmt = SQLite3::Statement.new(@db, "select ?")
      stmt.bind_param(1, 2 ** 31)
      result = nil
      stmt.each { |x| result = x }
      assert_equal [2 ** 31], result
    end

    def test_bind_double
      stmt = SQLite3::Statement.new(@db, "select ?")
      stmt.bind_param(1, 2.2)
      result = nil
      stmt.each { |x| result = x }
      assert_equal [2.2], result
    end

    def test_named_bind
      stmt = SQLite3::Statement.new(@db, "select :foo")
      stmt.bind_param(':foo', 'hello')
      result = nil
      stmt.each { |x| result = x }
      assert_equal ['hello'], result
    end

    def test_named_bind_no_colon
      stmt = SQLite3::Statement.new(@db, "select :foo")
      stmt.bind_param('foo', 'hello')
      result = nil
      stmt.each { |x| result = x }
      assert_equal ['hello'], result
    end

    def test_named_bind_symbol
      stmt = SQLite3::Statement.new(@db, "select :foo")
      stmt.bind_param(:foo, 'hello')
      result = nil
      stmt.each { |x| result = x }
      assert_equal ['hello'], result
    end

    def test_named_bind_not_found
      stmt = SQLite3::Statement.new(@db, "select :foo")
      assert_raises(SQLite3::Exception) do
        stmt.bind_param('bar', 'hello')
      end
    end

    def test_each
      r = nil
      @stmt.each do |row|
        r = row
      end
      assert_equal(['foo'], r)
    end

    def test_reset!
      r = []
      @stmt.each { |row| r << row }
      @stmt.reset!
      @stmt.each { |row| r << row }
      assert_equal [['foo'], ['foo']], r
    end

    def test_step
      r = @stmt.step
      assert_equal ['foo'], r
    end

    def test_tainted
      r = @stmt.step
      assert r.first.tainted?
    end

    def test_step_twice
      assert_not_nil @stmt.step
      assert !@stmt.done?
      assert_nil @stmt.step
      assert @stmt.done?

      @stmt.reset!
      assert !@stmt.done?
    end

    def test_step_never_moves_past_done
      10.times { @stmt.step }
      @stmt.done?
    end

    def test_column_count
      assert_equal 1, @stmt.column_count
    end

    def test_column_name
      assert_equal "'foo'", @stmt.column_name(0)
      assert_equal nil, @stmt.column_name(10)
    end

    def test_bind_parameter_count
      stmt = SQLite3::Statement.new(@db, "select ?, ?, ?")
      assert_equal 3, stmt.bind_parameter_count
    end

    def test_execute_with_varargs
      stmt = @db.prepare('select ?, ?')
      assert_equal [[nil, nil]], stmt.execute(nil, nil).to_a
    end

    def test_execute_with_hash
      stmt = @db.prepare('select :n, :h')
      assert_equal [[10, nil]], stmt.execute('n' => 10, 'h' => nil).to_a
    end

    def test_with_error
      @db.execute('CREATE TABLE "employees" ("name" varchar(20) NOT NULL CONSTRAINT "index_employees_on_name" UNIQUE)')
      stmt = @db.prepare("INSERT INTO Employees(name) VALUES(?)")
      stmt.execute('employee-1')
      stmt.execute('employee-1') rescue SQLite3::ConstraintException
      stmt.reset!
      assert stmt.execute('employee-2')
    end

    def test_clear_bindings
      stmt = @db.prepare('select ?, ?')
      stmt.bind_param 1, "foo"
      stmt.bind_param 2, "bar"

      # We can't fetch bound parameters back out of sqlite3, so just call
      # the clear_bindings! method and assert that nil is returned
      stmt.clear_bindings!

      while x = stmt.step
        assert_equal [nil, nil], x
      end
    end
  end
end
