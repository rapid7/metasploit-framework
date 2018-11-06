require 'helper'

class TC_OpenClose < SQLite3::TestCase
  def test_create_close
    begin
      db = SQLite3::Database.new( "test-create.db" )
      assert File.exist?( "test-create.db" )
      assert_nothing_raised { db.close }
    ensure
      File.delete( "test-create.db" ) rescue nil
    end
  end

  def test_open_close
    begin
      File.open( "test-open.db", "w" ) { |f| }
      assert File.exist?( "test-open.db" )
      db = SQLite3::Database.new( "test-open.db" )
      assert_nothing_raised { db.close }
    ensure
      File.delete( "test-open.db" ) rescue nil
    end
  end

  def test_bad_open
    assert_raise( SQLite3::CantOpenException ) do
      SQLite3::Database.new( "." )
    end
  end
end
