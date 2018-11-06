require 'helper'

module SQLite3
  class TestBackup < SQLite3::TestCase
    def setup
      @sdb = SQLite3::Database.new(':memory:')
      @ddb = SQLite3::Database.new(':memory:')
      @sdb.execute('CREATE TABLE foo (idx, val);');
      @data = ('A'..'Z').map{|x|x * 40}
      @data.each_with_index do |v, i|
        @sdb.execute('INSERT INTO foo (idx, val) VALUES (?, ?);', [i, v])
      end
    end

    def test_backup_step
      b = SQLite3::Backup.new(@ddb, 'main', @sdb, 'main')
      while b.step(1) == SQLite3::Constants::ErrorCode::OK
        assert_not_equal(0, b.remaining)
      end
      assert_equal(0, b.remaining)
      b.finish
      assert_equal(@data.length, @ddb.execute('SELECT * FROM foo;').length)
    end

    def test_backup_all
      b = SQLite3::Backup.new(@ddb, 'main', @sdb, 'main')
      assert_equal(SQLite3::Constants::ErrorCode::DONE, b.step(-1))
      assert_equal(0, b.remaining)
      b.finish
      assert_equal(@data.length, @ddb.execute('SELECT * FROM foo;').length)
    end
  end if defined?(SQLite3::Backup)
end
