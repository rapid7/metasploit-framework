require 'enumerator'

module Hashery

  # Hash with LRU expiry policy.  There are at most max_size elements in a
  # LRUHash.  When adding more elements old elements are removed according
  # to LRU policy.
  #
  # Based on Robert Klemme's LRUHash class.
  #
  # LRUHash, Copyright (c) 2010 Robert Klemme.
  #
  class LRUHash

    include Enumerable

    attr_reader :max_size

    attr_accessor :default
    attr_accessor :default_proc
    attr_accessor :release_proc

    #
    # Initialize new LRUHash instance.
    #
    # max_size      -
    # default_value -
    # block         -
    #
    def initialize(max_size, default_value=nil, &block)
      @max_size     = normalize_max(max_size)
      @default      = default_value
      @default_proc = block

      @h = {}
      @head = Node.new
      @tail = front(Node.new)
    end

    #
    # Iterate over each pair.
    #
    def each_pair
      if block_given?
        each_node do |n|
          yield [n.key, n.value]
        end
      else
        enum_for :each_pair
      end
    end

    #
    # Same as each pair.
    #
    alias each each_pair

    #
    # Iterate over each key.
    #
    def each_key
      if block_given?
        each_node do |n|
          yield n.key
        end
      else
        enum_for :each_key
      end
    end

    #
    # Iterate over each value.
    #
    def each_value
      if block_given?
        each_node do |n|
          yield n.value
        end
      else
        enum_for :each_value
      end
    end

    #
    # Size of the hash.
    #
    def size
      @h.size
    end

    #
    #
    #
    def empty?
      @head.succ.equal? @tail
    end

    #
    #
    #
    def fetch(key, &b)
      n = @h[key]

      if n
        front(n).value
      else
        (b || FETCH)[key]
      end
    end

    #
    #
    #
    def [](key)
      fetch(key) do |k|
        @default_proc ? @default_proc[self, k] : default
      end
    end

    #
    #
    #
    def keys
      @h.keys
    end

    #
    #
    #
    def values
      @h.map {|k,n| n.value}
    end

    #
    #
    #
    def has_key?(key)
      @h.has_key? key
    end

    alias key? has_key?
    alias member? has_key?
    alias include? has_key?

    #
    #
    #
    def has_value?(value)
      each_pair do |k, v|
        return true if value.eql? v
      end

      false
    end

    alias value? has_value?

    def values_at(*key_list)
      key_list.map {|k| self[k]}
    end

    #
    #
    #
    def assoc(key)
      n = @h[key]

      if n
        front(n)
        [n.key, n.value]
      end
    end

    #
    #
    #
    def rassoc(value)
      each_node do |n|
        if value.eql? n.value
          front(n)
          return [n.key, n.value]
        end
      end
      nil
    end

    #
    #
    #
    def key(value)
      pair = rassoc(value) and pair.first
    end

    #
    #
    #
    def store(key, value)
      # same optimization as in Hash
      key = key.dup.freeze if String === key && !key.frozen?

      n = @h[key]

      unless n
        if size == max_size
          # reuse node to optimize memory usage
          n = delete_oldest
          n.key = key
          n.value = value
        else
          n = Node.new key, value
        end

        @h[key] = n
      end

      front(n).value = value
    end

    alias []= store

    #
    #
    #
    def delete(key)
      n = @h[key] and remove_node(n).value
    end

    #
    #
    #
    def delete_if
      each_node do |n|
        remove_node n if yield n.key, n.value
      end
    end

    #
    #
    #
    def max_size=(limit)
      limit = normalize_max(limit)

      while size > limit
        delete_oldest
      end

      @max_size = limit
    end

    #
    #
    #
    def clear
      until empty?
        delete_oldest
      end

      self
    end

    #
    #
    #
    def to_s
      s = nil
      each_pair {|k, v| (s ? (s << ', ') : s = '{') << k.to_s << '=>' << v.to_s}
      s ? (s << '}') : '{}'
    end

    alias inspect to_s

  private

    #
    # Iterate nodes.
    #
    def each_node
      n = @head.succ

      until n.equal? @tail
        succ = n.succ
        yield n
        n = succ
      end

      self
    end

    #
    # Move node to front.
    #
    # node - [Node]
    #
    def front(node)
      node.insert_after(@head)
    end

    #
    # Remove the node and invoke release_proc
    # if set
    #
    # node - [Node]
    #
    def remove_node(node)
      n = @h.delete(node.key)
      n.unlink
      release_proc and release_proc[n.key, n.value]
      n
    end

    #
    # Remove the oldest node returning the node
    #
    def delete_oldest
      n = @tail.pred
      raise "Cannot delete from empty hash" if @head.equal? n
      remove_node n
    end

    #
    # Normalize the argument in order to be usable as max_size
    # criterion is that n.to_i must be an Integer and it must
    # be larger than zero.
    #
    # n - [#to_i] max size
    #
    def normalize_max(n)
      n = n.to_i
      raise ArgumentError, 'Invalid max_size: %p' % n unless Integer === n && n > 0
      n
    end

    #
    FETCH = Proc.new {|k| raise KeyError, 'key not found'}

    # A single node in the doubly linked LRU list of nodes.
    Node = Struct.new :key, :value, :pred, :succ do
      def unlink
        pred.succ = succ if pred
        succ.pred = pred if succ
        self.succ = self.pred = nil
        self
      end

      def insert_after(node)
        raise 'Cannot insert after self' if equal? node
        return self if node.succ.equal? self

        unlink

        self.succ = node.succ
        self.pred = node

        node.succ.pred = self if node.succ
        node.succ = self

        self
      end
    end

  end

end
