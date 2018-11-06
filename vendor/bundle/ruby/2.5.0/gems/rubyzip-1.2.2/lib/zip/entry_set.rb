module Zip
  class EntrySet #:nodoc:all
    include Enumerable
    attr_accessor :entry_set, :entry_order

    def initialize(an_enumerable = [])
      super()
      @entry_set = {}
      an_enumerable.each { |o| push(o) }
    end

    def include?(entry)
      @entry_set.include?(to_key(entry))
    end

    def find_entry(entry)
      @entry_set[to_key(entry)]
    end

    def <<(entry)
      @entry_set[to_key(entry)] = entry if entry
    end

    alias push <<

    def size
      @entry_set.size
    end

    alias length size

    def delete(entry)
      entry if @entry_set.delete(to_key(entry))
    end

    def each
      @entry_set = sorted_entries.dup.each do |_, value|
        yield(value)
      end
    end

    def entries
      sorted_entries.values
    end

    # deep clone
    def dup
      EntrySet.new(@entry_set.values.map(&:dup))
    end

    def ==(other)
      return false unless other.kind_of?(EntrySet)
      @entry_set.values == other.entry_set.values
    end

    def parent(entry)
      @entry_set[to_key(entry.parent_as_string)]
    end

    def glob(pattern, flags = ::File::FNM_PATHNAME | ::File::FNM_DOTMATCH | ::File::FNM_EXTGLOB)
      entries.map do |entry|
        next nil unless ::File.fnmatch(pattern, entry.name.chomp('/'), flags)
        yield(entry) if block_given?
        entry
      end.compact
    end

    protected

    def sorted_entries
      ::Zip.sort_entries ? Hash[@entry_set.sort] : @entry_set
    end

    private

    def to_key(entry)
      k = entry.to_s.chomp('/')
      k.downcase! if ::Zip.case_insensitive_match
      k
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
