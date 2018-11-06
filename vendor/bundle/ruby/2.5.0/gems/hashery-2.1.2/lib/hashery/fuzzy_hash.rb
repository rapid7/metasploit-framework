require 'set'

module Hashery

  # FuzzyHash is a weird hash with special semantics for regex keys.
  #
  # This is useful when you want to have a lookup table that can either contain strings or regexes.
  # For instance, you might want a catch all for certain regexes that perform a certain logic.
  #
  #  >> hash = FuzzyHash.new
  #  >> hash[/^\d+$/] = 'number'
  #  >> hash[/.*/] = 'something'
  #  >> hash['chunky'] = 'bacon'
  #  >> hash['foo'] = 'vader'
  #  
  #  >> hash['foo']
  #  << 'vader'
  #  >> hash['food']
  #  << 'something'
  #  >> hash['123']
  #  << 'number'
  #
  # This class is based on Joshua Hull's original FuzzyHash class.
  #
  class FuzzyHash

    #
    #
    #
    def initialize(init_hash = nil)
      @fuzzies = []
      @hash_reverse = {}
      @fuzzies_reverse = {}
      @fuzzy_hash = {}
      @hash = {}
      init_hash.each{ |key,value| self[key] = value } if init_hash
    end

    #
    #
    #
    def clear
      hash.clear
      fuzzies.clear
      hash_reverse.clear
      fuzzies_reverse.clear
    end

    #
    #
    #
    def size
      hash.size + fuzzies.size
    end

    alias_method :count, :size

    #
    #
    #
    def ==(o)
      o.is_a?(FuzzyHash)
      o.send(:hash) == hash &&
      o.send(:fuzzies) == fuzzies
    end

    #
    #
    #
    def empty?
      hash.empty? && fuzzies.empty?
    end

    #
    #
    #
    def keys
      hash.keys + fuzzy_hash.keys
    end

    #
    #
    #
    def values
      hash.values + fuzzies.collect{|r| r.last}
    end

    #
    #
    #
    def each
      hash.each{|k,v| yield k,v }
      fuzzies.each{|v| yield v.first, v.last }
    end

    #
    #
    #
    def delete_value(value)
      hash.delete(hash_reverse[value]) || ((rr = fuzzies_reverse[value]) && fuzzies.delete_at(rr[0]))
    end

    #
    #
    #
    def []=(key, value)
      if Regexp === key
        fuzzies.delete_if{|f| f.first.inspect.hash == key.inspect.hash}
        fuzzies_reverse.delete_if{|k, v| v[1].inspect.hash == key.inspect.hash}
        hash_reverse.delete_if{|k,v| v.inspect.hash == key.inspect.hash}

        fuzzy_hash[key] = value
        fuzzies << [key, value]
        reset_fuzz_test!
        fuzzies_reverse[value] = [fuzzies.size - 1, key, value]
      else
        hash[key] = value
        hash_reverse.delete_if{|k,v| v.hash == key.hash}
        hash_reverse[value] = key
      end
      value
    end

    #
    #
    #
    def replace(src, dest)
      if hash_reverse.key?(src)
        key = hash_reverse[src]
        hash[key] = dest
        hash_reverse.delete(src)
        hash_reverse[dest] = key
      elsif fuzzies_reverse.key?(src)
        key = fuzzies_reverse[src]
        fuzzies[rkey[0]] = [rkey[1], dest]
        fuzzies_reverse.delete(src)
        fuzzies_reverse[dest] = [rkey[0], rkey[1], dest]
      end
    end

    #
    #
    #
    def [](key)
      (hash.key?(key) && hash[key])  ||
        ((lookup = fuzzy_lookup(key)) && lookup && lookup.first) ||
        fuzzy_hash[key]
    end

    #
    #
    #
    def match_with_result(key)
      if hash.key?(key)
        [hash[key], key]
      else
        fuzzy_lookup(key)
      end
    end

  private

    attr_reader :fuzzies, :hash_reverse, :fuzzies_reverse, :hash, :fuzzy_hash
    attr_writer :fuzz_test

    #
    #
    #
    def reset_fuzz_test!
      self.fuzz_test = nil
    end

    #
    #
    #
    def fuzz_test
      unless @fuzz_test
        @fuzz_test = Object.new
        @fuzz_test.instance_variable_set(:'@fuzzies', fuzzies)
        method = "
          def match(str)
            case str\n
        "
        fuzzies.each_with_index do |reg, index|
          method << "when #{reg.first.inspect}; [@fuzzies[#{index}][1], Regexp.last_match(0)];"
        end
        method << "end\nend\n"
        @fuzz_test.instance_eval method
      end
      @fuzz_test
    end

    #
    #
    #
    def fuzzy_lookup(key)
      if !fuzzies.empty? && (value = fuzz_test.match(key))
        value
      end
    end

  end

end

# Copyright (c) 2009 Joshua Hull
