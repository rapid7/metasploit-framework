# -*- coding: utf-8 -*-

require 'helper'

module SQLite3
  class TestCollation < SQLite3::TestCase
    class Comparator
      attr_reader :calls
      def initialize
        @calls = []
      end

      def compare left, right
        @calls << [left, right]
        left <=> right
      end
    end

    def setup
      @db = SQLite3::Database.new(':memory:')
      @create = "create table ex(id int, data string)"
      @db.execute(@create);
      [ [1, 'hello'], [2, 'world'] ].each do |vals|
        @db.execute('insert into ex (id, data) VALUES (?, ?)', vals)
      end
    end

    def test_custom_collation
      comparator = Comparator.new

      @db.collation 'foo', comparator

      assert_equal comparator, @db.collations['foo']
      @db.execute('select data from ex order by 1 collate foo')
      assert_equal 1, comparator.calls.length
    end

    def test_remove_collation
      comparator = Comparator.new

      @db.collation 'foo', comparator
      @db.collation 'foo', nil

      assert_nil @db.collations['foo']
      assert_raises(SQLite3::SQLException) do
        @db.execute('select data from ex order by 1 collate foo')
      end
    end

    if RUBY_VERSION >= '1.9.1'
      def test_encoding
        comparator = Comparator.new
        @db.collation 'foo', comparator
        @db.execute('select data from ex order by 1 collate foo')

        a, b = *comparator.calls.first

        assert_equal Encoding.find('UTF-8'), a.encoding
        assert_equal Encoding.find('UTF-8'), b.encoding
      end

      def test_encoding_default_internal
        warn_before = $-w
        $-w = false
        before_enc = Encoding.default_internal

        Encoding.default_internal = 'EUC-JP'
        comparator = Comparator.new
        @db.collation 'foo', comparator
        @db.execute('select data from ex order by 1 collate foo')

        a, b = *comparator.calls.first

        assert_equal Encoding.find('EUC-JP'), a.encoding
        assert_equal Encoding.find('EUC-JP'), b.encoding
      ensure
        Encoding.default_internal = before_enc
        $-w = warn_before
      end
    end
  end
end
