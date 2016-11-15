require 'pstore'
require 'forwardable'

module Anemone
  module Storage
    class PStore
      extend Forwardable

      def_delegators :@keys, :has_key?, :keys, :size

      def initialize(file)
        File.delete(file) if File.exist?(file)
        @store = ::PStore.new(file)
        @keys = {}
      end

      def [](key)
        @store.transaction { |s| s[key] }
      end

      def []=(key,value)
        @keys[key] = nil
        @store.transaction { |s| s[key] = value }
      end

      def delete(key)
        @keys.delete(key)
        @store.transaction { |s| s.delete key}
      end

      def each
        @keys.each_key do |key|
          value = nil
          @store.transaction { |s| value = s[key] }
          yield key, value
        end
      end

      def merge!(hash)
        @store.transaction do |s|
          hash.each { |key, value| s[key] = value; @keys[key] = nil }
        end
        self
      end

      def close; end

    end
  end
end
