require 'helper'

class TC_ResultSet < SQLite3::TestCase
  def setup
    @db = SQLite3::Database.new(":memory:")
    @db.transaction do
      @db.execute "create table foo ( a integer primary key, b text )"
      @db.execute "insert into foo ( b ) values ( 'foo' )"
      @db.execute "insert into foo ( b ) values ( 'bar' )"
      @db.execute "insert into foo ( b ) values ( 'baz' )"
    end
    @stmt = @db.prepare( "select * from foo where a in ( ?, ? )" )
    @result = @stmt.execute
  end

  def teardown
    @stmt.close
    @db.close
  end

  def test_reset_unused
    assert_nothing_raised { @result.reset }
    assert @result.to_a.empty?
  end

  def test_reset_used
    @result.to_a
    assert_nothing_raised { @result.reset }
    assert @result.to_a.empty?
  end

  def test_reset_with_bind
    @result.to_a
    assert_nothing_raised { @result.reset( 1, 2 ) }
    assert_equal 2, @result.to_a.length
  end

  def test_eof_inner
    @result.reset( 1 )
    assert !@result.eof?
  end

  def test_eof_edge
    @result.reset( 1 )
    @result.next # to first row
    @result.next # to end of result set
    assert @result.eof?
  end

  def test_next_eof
    @result.reset( 1 )
    assert_not_nil @result.next
    assert_nil @result.next
  end

  def test_next_no_type_translation_no_hash
    @result.reset( 1 )
    assert_equal [ 1, "foo" ], @result.next
  end

  def test_next_type_translation
    @result.reset( 1 )
    assert_equal [ 1, "foo" ], @result.next
  end

  def test_next_type_translation_with_untyped_column
    @db.query( "select count(*) from foo" ) do |result|
      assert_equal [3], result.next
    end
  end

  def test_type_translation_with_null_column
    time = '1974-07-25 14:39:00'

    @db.execute "create table bar ( a integer, b time, c string )"
    @db.execute "insert into bar (a, b, c) values (NULL, '#{time}', 'hello')"
    @db.execute "insert into bar (a, b, c) values (1, NULL, 'hello')"
    @db.execute "insert into bar (a, b, c) values (2, '#{time}', NULL)"
    @db.query( "select * from bar" ) do |result|
      assert_equal [nil, time, 'hello'], result.next
      assert_equal [1, nil, 'hello'], result.next
      assert_equal [2, time, nil], result.next
    end
  end

  def test_real_translation
    @db.execute('create table foo_real(a real)')
    @db.execute('insert into foo_real values (42)' )
    @db.query('select a, sum(a), typeof(a), typeof(sum(a)) from foo_real') do |result|
      result = result.next
      assert result[0].is_a?(Float)
      assert result[1].is_a?(Float)
      assert result[2].is_a?(String)
      assert result[3].is_a?(String)
    end
  end

  def test_next_results_as_hash
    @db.results_as_hash = true
    @result.reset( 1 )
    hash = @result.next
    assert_equal( { "a" => 1, "b" => "foo" },
      hash )
    assert_equal hash[0], 1
    assert_equal hash[1], "foo"
  end

  def test_tainted_results_as_hash
    @db.results_as_hash = true
    @result.reset( 1 )
    row = @result.next
    row.each do |_, v|
      assert(v.tainted?) if String === v
    end
  end

  def test_tainted_row_values
    @result.reset( 1 )
    row = @result.next
    row.each do |v|
      assert(v.tainted?) if String === v
    end
  end

  def test_each
    called = 0
    @result.reset( 1, 2 )
    @result.each { |row| called += 1 }
    assert_equal 2, called
  end

  def test_enumerable
    @result.reset( 1, 2 )
    assert_equal 2, @result.to_a.length
  end

  def test_types
    assert_equal [ "integer", "text" ], @result.types
  end

  def test_columns
    assert_equal [ "a", "b" ], @result.columns
  end

  def test_close
    stmt = @db.prepare( "select * from foo" )
    result = stmt.execute
    assert !result.closed?
    result.close
    assert result.closed?
    assert stmt.closed?
    assert_raise( SQLite3::Exception ) { result.reset }
    assert_raise( SQLite3::Exception ) { result.next }
    assert_raise( SQLite3::Exception ) { result.each }
    assert_raise( SQLite3::Exception ) { result.close }
    assert_raise( SQLite3::Exception ) { result.types }
    assert_raise( SQLite3::Exception ) { result.columns }
  end
end
