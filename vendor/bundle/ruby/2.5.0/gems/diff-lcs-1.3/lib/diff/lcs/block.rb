# -*- ruby encoding: utf-8 -*-

# A block is an operation removing, adding, or changing a group of items.
# Basically, this is just a list of changes, where each change adds or
# deletes a single item. Used by bin/ldiff.
class Diff::LCS::Block
  attr_reader :changes, :insert, :remove

  def initialize(chunk)
    @changes = []
    @insert = []
    @remove = []

    chunk.each do |item|
      @changes << item
      @remove << item if item.deleting?
      @insert << item if item.adding?
    end
  end

  def diff_size
    @insert.size - @remove.size
  end

  def op
    case [@remove.empty?, @insert.empty?]
    when [false, false]
      '!'
    when [false, true]
      '-'
    when [true, false]
      '+'
    else # [true, true]
      '^'
    end
  end
end
