begin
  require 'sqlite3'
rescue LoadError
  puts "You need the sqlite3 gem to use Anemone::Storage::SQLite3"
  exit
end

module Anemone
  module Storage
    class SQLite3

      def initialize(file)
        @db = ::SQLite3::Database.new(file)
        create_schema
      end

      def [](url)
        value = @db.get_first_value('SELECT data FROM anemone_storage WHERE key = ?', url.to_s)
        if value
          Marshal.load(value)
        end
      end

      def []=(url, value)
        data = Marshal.dump(value)
        if has_key?(url)
          @db.execute('UPDATE anemone_storage SET data = ? WHERE key = ?', data, url.to_s)
        else
          @db.execute('INSERT INTO anemone_storage (data, key) VALUES(?, ?)', data, url.to_s)
        end
      end

      def delete(url)
        page = self[url]
        @db.execute('DELETE FROM anemone_storage WHERE key = ?', url.to_s)
        page
      end

      def each
        @db.execute("SELECT key, data FROM anemone_storage ORDER BY id") do |row|
          value = Marshal.load(row[1])
          yield row[0], value
        end
      end

      def merge!(hash)
        hash.each { |key, value| self[key] = value }
        self
      end

      def size
        @db.get_first_value('SELECT COUNT(id) FROM anemone_storage')
      end

      def keys
        @db.execute("SELECT key FROM anemone_storage ORDER BY id").map{|t| t[0]}
      end

      def has_key?(url)
        !!@db.get_first_value('SELECT id FROM anemone_storage WHERE key = ?', url.to_s)
      end

      def close
        @db.close
      end

      private

      def create_schema
        @db.execute_batch <<SQL
          create table if not exists anemone_storage (
            id INTEGER PRIMARY KEY ASC,
            key TEXT,
            data BLOB
          );
          create index  if not exists anemone_key_idx on anemone_storage (key);
SQL
      end

      def load_page(hash)
        BINARY_FIELDS.each do |field|
          hash[field] = hash[field].to_s
        end
        Page.from_hash(hash)
      end

    end
  end
end
