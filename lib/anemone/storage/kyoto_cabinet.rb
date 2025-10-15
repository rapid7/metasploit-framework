begin
  require 'kyotocabinet'
rescue LoadError
  puts $!
  puts "You need the kyotocabinet-ruby gem to use Anemone::Storage::KyotoCabinet"
  exit
end

require 'forwardable'

module Anemone
  module Storage
    class KyotoCabinet
      extend Forwardable

      def_delegators :@db, :close, :size, :each

      def initialize(file)
        raise "KyotoCabinet filename must have .kch extension" if File.extname(file) != '.kch'
        @db = ::KyotoCabinet::DB::new
        @db.open(file, ::KyotoCabinet::DB::OWRITER | ::KyotoCabinet::DB::OCREATE)
        @db.clear
      end

      def [](key)
        if value = @db[key]
          load_value(value)
        end
      end

      def []=(key, value)
        @db[key] = [Marshal.dump(value)].pack("m")
      end

      def each
        @db.each do |k, v|
          yield(k, load_value(v))
        end
      end

      def has_key?(key)
        # Kyoto Cabinet doesn't have a way to query whether a key exists, so hack it
        keys = @db.match_prefix(key)
        !!keys && keys.include?(key)
      end

      def keys
        acc = []
        @db.each_key { |key| acc << key.first }
        acc
      end

      def delete(key)
        value = self[key]
        @db.delete(key)
        value
      end

      def merge!(hash)
        hash.each { |key, value| self[key] = value }
        self
      end

      private

      def load_value(value)
        Marshal.load(value.unpack("m")[0])
      end

    end
  end
end
