# coding: utf-8

require 'hashery/lru_hash'

class PDF::Reader

  # A Hash-like object for caching commonly used objects from a PDF file.
  #
  # This is an internal class, no promises about a stable API.
  #
  class ObjectCache # nodoc

    # These object types use little memory and are accessed a heap of times as
    # part of random page access, so we'll cache the unmarshalled objects and
    # avoid lots of repetitive (and expensive) tokenising
    CACHEABLE_TYPES = [:Catalog, :Page, :Pages]

    attr_reader :hits, :misses

    def initialize(lru_size = 1000)
      @objects = {}
      @lru_cache = Hashery::LRUHash.new(lru_size.to_i)
      @hits = 0
      @misses = 0
    end

    def [](key)
      update_stats(key)
      @objects[key] || @lru_cache[key]
    end

    def []=(key, value)
      if cacheable?(value)
        @objects[key] = value
      else
        @lru_cache[key] = value
      end
    end

    def fetch(key, local_default = nil)
      update_stats(key)
      @objects[key] || @lru_cache.fetch(key, local_default)
    end

    def each(&block)
      @objects.each(&block)
      @lru_cache.each(&block)
    end
    alias :each_pair :each

    def each_key(&block)
      @objects.each_key(&block)
      @lru_cache.each_key(&block)
    end

    def each_value(&block)
      @objects.each_value(&block)
      @lru_cache.each_value(&block)
    end

    def size
      @objects.size + @lru_cache.size
    end
    alias :length :size

    def empty?
      @objects.empty? && @lru_cache.empty?
    end

    def include?(key)
      @objects.include?(key) || @lru_cache.include?(key)
    end
    alias :has_key? :include?
    alias :key? :include?
    alias :member? :include?

    def has_value?(value)
      @objects.has_value?(value) || @lru_cache.has_value?(value)
    end

    def to_s
      "<PDF::Reader::ObjectCache size: #{self.size}>"
    end

    def keys
      @objects.keys + @lru_cache.keys
    end

    def values
      @objects.values + @lru_cache.values
    end

    private

    def update_stats(key)
      if has_key?(key)
        @hits += 1
      else
        @misses += 1
      end
    end

    def cacheable?(obj)
      obj.is_a?(Hash) && CACHEABLE_TYPES.include?(obj[:Type])
    end

  end
end
