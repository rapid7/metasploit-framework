require 'helper'

class TC_Database_Integration < SQLite3::TestCase
  def setup
    @db = SQLite3::Database.new(":memory:")
    @db.transaction do
      @db.execute "create table foo ( a integer primary key, b text )"
      @db.execute "insert into foo ( b ) values ( 'foo' )"
      @db.execute "insert into foo ( b ) values ( 'bar' )"
      @db.execute "insert into foo ( b ) values ( 'baz' )"
    end
  end

  def teardown
    @db.close
  end

  def test_table_info_with_type_translation_active
    assert_nothing_raised { @db.table_info("foo") }
  end

  def test_table_info_with_defaults_for_version_3_3_8_and_higher
    @db.transaction do
      @db.execute "create table defaults_test ( a string default NULL, b string default 'Hello', c string default '--- []\n' )"
      data = @db.table_info( "defaults_test" )
      assert_equal({"name" => "a", "type" => "string", "dflt_value" => nil, "notnull" => 0, "cid" => 0, "pk" => 0},
        data[0])
      assert_equal({"name" => "b", "type" => "string", "dflt_value" => "Hello", "notnull" => 0, "cid" => 1, "pk" => 0},
        data[1])
      assert_equal({"name" => "c", "type" => "string", "dflt_value" => "--- []\n", "notnull" => 0, "cid" => 2, "pk" => 0},
        data[2])
    end
  end

  def test_table_info_without_defaults_for_version_3_3_8_and_higher
    @db.transaction do
      @db.execute "create table no_defaults_test ( a integer default 1, b integer )"
      data = @db.table_info( "no_defaults_test" )
      assert_equal({"name" => "a", "type" => "integer", "dflt_value" => "1", "notnull" => 0, "cid" => 0, "pk" => 0},
        data[0])
      assert_equal({"name" => "b", "type" => "integer", "dflt_value" => nil, "notnull" => 0, "cid" => 1, "pk" => 0},
        data[1])
    end
  end

  def test_complete_fail
    assert !@db.complete?( "select * from foo" )
  end
  def test_complete_success
    assert @db.complete?( "select * from foo;" )
  end

  # FIXME: do people really need UTF16 sql statements?
  #def test_complete_fail_utf16
  #  assert !@db.complete?( "select * from foo".to_utf16(false), true )
  #end

  # FIXME: do people really need UTF16 sql statements?
  #def test_complete_success_utf16
  #  assert @db.complete?( "select * from foo;".to_utf16(true), true )
  #end

  def test_errmsg
    assert_equal "not an error", @db.errmsg
  end

  # FIXME: do people really need UTF16 error messages?
  #def test_errmsg_utf16
  #  msg = Iconv.conv('UTF-16', 'UTF-8', 'not an error')
  #  assert_equal msg, @db.errmsg(true)
  #end

  def test_errcode
    assert_equal 0, @db.errcode
  end

  def test_trace
    result = nil
    @db.trace { |sql| result = sql }
    @db.execute "select * from foo"
    assert_equal "select * from foo", result
  end

  def test_authorizer_okay
    @db.authorizer { |type,a,b,c,d| 0 }
    rows = @db.execute "select * from foo"
    assert_equal 3, rows.length
  end

  def test_authorizer_error
    @db.authorizer { |type,a,b,c,d| 1 }
    assert_raise( SQLite3::AuthorizationException ) do
      @db.execute "select * from foo"
    end
  end

  def test_authorizer_silent
    @db.authorizer { |type,a,b,c,d| 2 }
    rows = @db.execute "select * from foo"
    assert rows.empty?
  end

  def test_prepare_invalid_syntax
    assert_raise( SQLite3::SQLException ) do
      @db.prepare "select from foo"
    end
  end

  def test_prepare_invalid_column
    assert_raise( SQLite3::SQLException ) do
      @db.prepare "select k from foo"
    end
  end

  def test_prepare_invalid_table
    assert_raise( SQLite3::SQLException ) do
      @db.prepare "select * from barf"
    end
  end

  def test_prepare_no_block
    stmt = @db.prepare "select * from foo"
    assert stmt.respond_to?(:execute)
    stmt.close
  end

  def test_prepare_with_block
    called = false
    @db.prepare "select * from foo" do |stmt|
      called = true
      assert stmt.respond_to?(:execute)
    end
    assert called
  end

  def test_execute_no_block_no_bind_no_match
    rows = @db.execute( "select * from foo where a > 100" )
    assert rows.empty?
  end

  def test_execute_with_block_no_bind_no_match
    called = false
    @db.execute( "select * from foo where a > 100" ) do |row|
      called = true
    end
    assert !called
  end

  def test_execute_no_block_with_bind_no_match
    rows = @db.execute( "select * from foo where a > ?", 100 )
    assert rows.empty?
  end

  def test_execute_with_block_with_bind_no_match
    called = false
    @db.execute( "select * from foo where a > ?", 100 ) do |row|
      called = true
    end
    assert !called
  end

  def test_execute_no_block_no_bind_with_match
    rows = @db.execute( "select * from foo where a = 1" )
    assert_equal 1, rows.length
  end

  def test_execute_with_block_no_bind_with_match
    called = 0
    @db.execute( "select * from foo where a = 1" ) do |row|
      called += 1
    end
    assert_equal 1, called
  end

  def test_execute_no_block_with_bind_with_match
    rows = @db.execute( "select * from foo where a = ?", 1 )
    assert_equal 1, rows.length
  end

  def test_execute_with_block_with_bind_with_match
    called = 0
    @db.execute( "select * from foo where a = ?", 1 ) do |row|
      called += 1
    end
    assert_equal 1, called
  end

  def test_execute2_no_block_no_bind_no_match
    columns, *rows = @db.execute2( "select * from foo where a > 100" )
    assert rows.empty?
    assert_equal [ "a", "b" ], columns
  end

  def test_execute2_with_block_no_bind_no_match
    called = 0
    @db.execute2( "select * from foo where a > 100" ) do |row|
      assert [ "a", "b" ], row unless called == 0
      called += 1
    end
    assert_equal 1, called
  end

  def test_execute2_no_block_with_bind_no_match
    columns, *rows = @db.execute2( "select * from foo where a > ?", 100 )
    assert rows.empty?
    assert_equal [ "a", "b" ], columns
  end

  def test_execute2_with_block_with_bind_no_match
    called = 0
    @db.execute2( "select * from foo where a > ?", 100 ) do |row|
      assert_equal [ "a", "b" ], row unless called == 0
      called += 1
    end
    assert_equal 1, called
  end

  def test_execute2_no_block_no_bind_with_match
    columns, *rows = @db.execute2( "select * from foo where a = 1" )
    assert_equal 1, rows.length
    assert_equal [ "a", "b" ], columns
  end

  def test_execute2_with_block_no_bind_with_match
    called = 0
    @db.execute2( "select * from foo where a = 1" ) do |row|
      assert_equal [ 1, "foo" ], row unless called == 0
      called += 1
    end
    assert_equal 2, called
  end

  def test_execute2_no_block_with_bind_with_match
    columns, *rows = @db.execute2( "select * from foo where a = ?", 1 )
    assert_equal 1, rows.length
    assert_equal [ "a", "b" ], columns
  end

  def test_execute2_with_block_with_bind_with_match
    called = 0
    @db.execute2( "select * from foo where a = ?", 1 ) do
      called += 1
    end
    assert_equal 2, called
  end

  def test_execute_batch_empty
    assert_nothing_raised { @db.execute_batch "" }
  end

  def test_execute_batch_no_bind
    @db.transaction do
      @db.execute_batch <<-SQL
        create table bar ( a, b, c );
        insert into bar values ( 'one', 2, 'three' );
        insert into bar values ( 'four', 5, 'six' );
        insert into bar values ( 'seven', 8, 'nine' );
      SQL
    end
    rows = @db.execute( "select * from bar" )
    assert_equal 3, rows.length
  end

  def test_execute_batch_with_bind
    @db.execute_batch( <<-SQL, [1] )
      create table bar ( a, b, c );
      insert into bar values ( 'one', 2, ? );
      insert into bar values ( 'four', 5, ? );
      insert into bar values ( 'seven', 8, ? );
    SQL
    rows = @db.execute( "select * from bar" ).map { |a,b,c| c }
    assert_equal [1, 1, 1], rows
  end

  def test_query_no_block_no_bind_no_match
    result = @db.query( "select * from foo where a > 100" )
    assert_nil result.next
    result.close
  end

  def test_query_with_block_no_bind_no_match
    r = nil
    @db.query( "select * from foo where a > 100" ) do |result|
      assert_nil result.next
      r = result
    end
    assert r.closed?
  end

  def test_query_no_block_with_bind_no_match
    result = @db.query( "select * from foo where a > ?", 100 )
    assert_nil result.next
    result.close
  end

  def test_query_with_block_with_bind_no_match
    r = nil
    @db.query( "select * from foo where a > ?", 100 ) do |result|
      assert_nil result.next
      r = result
    end
    assert r.closed?
  end

  def test_query_no_block_no_bind_with_match
    result = @db.query( "select * from foo where a = 1" )
    assert_not_nil result.next
    assert_nil result.next
    result.close
  end

  def test_query_with_block_no_bind_with_match
    r = nil
    @db.query( "select * from foo where a = 1" ) do |result|
      assert_not_nil result.next
      assert_nil result.next
      r = result
    end
    assert r.closed?
  end

  def test_query_no_block_with_bind_with_match
    result = @db.query( "select * from foo where a = ?", 1 )
    assert_not_nil result.next
    assert_nil result.next
    result.close
  end

  def test_query_with_block_with_bind_with_match
    r = nil
    @db.query( "select * from foo where a = ?", 1 ) do |result|
      assert_not_nil result.next
      assert_nil result.next
      r = result
    end
    assert r.closed?
  end

  def test_get_first_row_no_bind_no_match
    result = @db.get_first_row( "select * from foo where a=100" )
    assert_nil result
  end

  def test_get_first_row_no_bind_with_match
    result = @db.get_first_row( "select * from foo where a=1" )
    assert_equal [ 1, "foo" ], result
  end

  def test_get_first_row_with_bind_no_match
    result = @db.get_first_row( "select * from foo where a=?", 100 )
    assert_nil result
  end

  def test_get_first_row_with_bind_with_match
    result = @db.get_first_row( "select * from foo where a=?", 1 )
    assert_equal [ 1, "foo" ], result
  end

  def test_get_first_value_no_bind_no_match
    result = @db.get_first_value( "select b, a from foo where a=100" )
    assert_nil result
  end

  def test_get_first_value_no_bind_with_match
    result = @db.get_first_value( "select b, a from foo where a=1" )
    assert_equal "foo", result
  end

  def test_get_first_value_with_bind_no_match
    result = @db.get_first_value( "select b, a from foo where a=?", 100 )
    assert_nil result
  end

  def test_get_first_value_with_bind_with_match
    result = @db.get_first_value( "select b, a from foo where a=?", 1 )
    assert_equal "foo", result
  end

  def test_last_insert_row_id
    @db.execute "insert into foo ( b ) values ( 'test' )"
    assert_equal 4, @db.last_insert_row_id
    @db.execute "insert into foo ( b ) values ( 'again' )"
    assert_equal 5, @db.last_insert_row_id
  end

  def test_changes
    @db.execute "insert into foo ( b ) values ( 'test' )"
    assert_equal 1, @db.changes
    @db.execute "delete from foo where 1=1"
    assert_equal 4, @db.changes
  end

  def test_total_changes
    assert_equal 3, @db.total_changes
    @db.execute "insert into foo ( b ) values ( 'test' )"
    @db.execute "delete from foo where 1=1"
    assert_equal 8, @db.total_changes
  end

  def test_transaction_nest
    assert_raise( SQLite3::SQLException ) do
      @db.transaction do
        @db.transaction do
        end
      end
    end
  end

  def test_transaction_rollback
    @db.transaction
    @db.execute_batch <<-SQL
      insert into foo (b) values ( 'test1' );
      insert into foo (b) values ( 'test2' );
      insert into foo (b) values ( 'test3' );
      insert into foo (b) values ( 'test4' );
    SQL
    assert_equal 7, @db.get_first_value("select count(*) from foo").to_i
    @db.rollback
    assert_equal 3, @db.get_first_value("select count(*) from foo").to_i
  end

  def test_transaction_commit
    @db.transaction
    @db.execute_batch <<-SQL
      insert into foo (b) values ( 'test1' );
      insert into foo (b) values ( 'test2' );
      insert into foo (b) values ( 'test3' );
      insert into foo (b) values ( 'test4' );
    SQL
    assert_equal 7, @db.get_first_value("select count(*) from foo").to_i
    @db.commit
    assert_equal 7, @db.get_first_value("select count(*) from foo").to_i
  end

  def test_transaction_rollback_in_block
    assert_raise( SQLite3::SQLException ) do
      @db.transaction do
        @db.rollback
      end
    end
  end

  def test_transaction_commit_in_block
    assert_raise( SQLite3::SQLException ) do
      @db.transaction do
        @db.commit
      end
    end
  end

  def test_transaction_active
    assert !@db.transaction_active?
    @db.transaction
    assert @db.transaction_active?
    @db.commit
    assert !@db.transaction_active?
  end

  def test_transaction_implicit_rollback
    assert !@db.transaction_active?
    @db.transaction 
    @db.execute('create table bar (x CHECK(1 = 0))')
    assert @db.transaction_active?
    assert_raises( SQLite3::ConstraintException ) do
      @db.execute("insert or rollback into bar (x) VALUES ('x')")
    end
    assert !@db.transaction_active?
  end

  def test_interrupt
    @db.create_function( "abort", 1 ) do |func,x|
      @db.interrupt
      func.result = x
    end

    assert_raise( SQLite3::InterruptException ) do
      @db.execute "select abort(a) from foo"
    end
  end

  def test_create_function
    @db.create_function( "munge", 1 ) do |func,x|
      func.result = ">>>#{x}<<<"
    end

    value = @db.get_first_value( "select munge(b) from foo where a=1" )
    assert_match( />>>.*<<</, value )
  end

  def test_create_aggregate_without_block
    step = proc do |ctx,a|
      ctx[:sum] ||= 0
      ctx[:sum] += a.to_i
    end

    final = proc { |ctx| ctx.result = ctx[:sum] }

    @db.create_aggregate( "accumulate", 1, step, final )

    value = @db.get_first_value( "select accumulate(a) from foo" )
    assert_equal 6, value

    # calling #get_first_value twice don't add up to the latest result
    value = @db.get_first_value( "select accumulate(a) from foo" )
    assert_equal 6, value
  end

  def test_create_aggregate_with_block
    @db.create_aggregate( "accumulate", 1 ) do
      step do |ctx,a|
        ctx[:sum] ||= 0
        ctx[:sum] += a.to_i
      end

      finalize { |ctx| ctx.result = ctx[:sum] }
    end

    value = @db.get_first_value( "select accumulate(a) from foo" )
    assert_equal 6, value
  end

  def test_create_aggregate_with_no_data
    @db.create_aggregate( "accumulate", 1 ) do
      step do |ctx,a|
        ctx[:sum] ||= 0
        ctx[:sum] += a.to_i
      end

      finalize { |ctx| ctx.result = ctx[:sum] || 0 }
    end

    value = @db.get_first_value(
      "select accumulate(a) from foo where a = 100" )
    assert_equal 0, value
  end

  class AggregateHandler
    class << self
      def arity; 1; end
      def text_rep; SQLite3::Constants::TextRep::ANY; end
      def name; "multiply"; end
    end
    def step(ctx, a)
      ctx[:buffer] ||= 1
      ctx[:buffer] *= a.to_i
    end
    def finalize(ctx); ctx.result = ctx[:buffer]; end
  end

  def test_aggregate_initialized_twice
    initialized = 0
    handler = Class.new(AggregateHandler) do
      define_method(:initialize) do
        initialized += 1
        super()
      end
    end

    @db.create_aggregate_handler handler
    @db.get_first_value( "select multiply(a) from foo" )
    @db.get_first_value( "select multiply(a) from foo" )
    assert_equal 2, initialized
  end

  def test_create_aggregate_handler
    @db.create_aggregate_handler AggregateHandler
    value = @db.get_first_value( "select multiply(a) from foo" )
    assert_equal 6, value
  end

  def test_bind_array_parameter
    result = @db.get_first_value( "select b from foo where a=? and b=?",
      [ 1, "foo" ] )
    assert_equal "foo", result
  end
end
