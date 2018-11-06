require 'enumerator'

module Hashery

  # LinkedList implements a simple doubly linked list with efficient
  # hash-like element access.
  #
  # This is a simple linked-list implementation with efficient random
  # access of data elements.  It was inspired by George Moscovitis'
  # LRUCache implementation found in Facets 1.7.30, but unlike the
  # linked-list in that cache, this one does not require the use of a
  # mixin on any class to be stored.  The linked-list provides the
  # push, pop, shift, unshift, first, last, delete and length methods
  # which work just like their namesakes in the Array class, but it
  # also supports setting and retrieving values by key, just like a
  # hash.
  #
  # LinkedList was ported from the original in Kirk Hanes IOWA web framework.
  #
  # == Acknowledgements
  #
  # LinkedList is based on the LinkedList library by Kirk Haines.
  #
  # Copyright (C) 2006 Kirk Haines <khaines@enigo.com>.
  #
  class LinkedList

    include Enumerable

    # Represents a single node of the linked list.
    #
    class Node
      attr_accessor :key, :value, :prev_node, :next_node

      def initialize(key=nil,value=nil,prev_node=nil,next_node=nil)
        @key = key
        @value = value
        @prev_node = prev_node
        @next_node = next_node
      end
    end

    #
    # Initialize new LinkedList instance.
    #
    def initialize
      @head   = Node.new
      @tail   = Node.new
      @lookup = Hash.new

      node_join(@head,@tail)
    end

    #
    # Lookup entry by key.
    #
    def [](key)
      @lookup[key].value
    end

    #
    # Add node to linked list.
    #
    def []=(k,v)
      if @lookup.has_key?(k)
        @lookup[k].value = v
      else
        n = Node.new(k,v,@head,@head.next_node)
        node_join(n,@head.next_node)
        node_join(@head,n)
        @lookup[k] = n
      end
      v
    end

    #
    # Is linked list empty?
    #
    def empty?
      @lookup.empty?
    end

    #
    # Remove node idenified by key.
    #
    def delete(key)
      n = @lookup.delete(key)
      v = n ? node_purge(n) : nil
      v
    end

    #
    # Get value of first node.
    #
    def first
      @head.next_node.value
    end

    #
    # Get value of last node.
    #
    def last
      @tail.prev_node.value
    end

    #
    #
    #
    def shift
      k = @head.next_node.key
      n = @lookup.delete(k)
      node_delete(n) if n
    end

    #
    #
    #
    def unshift(v)
      if @lookup.has_key?(v)
        n = @lookup[v]
        node_delete(n)
        node_join(n,@head.next_node)
        node_join(@head,n)
      else
        n = Node.new(v,v,@head,@head.next_node)
        node_join(n,@head.next_node)
        node_join(@head,n)
        @lookup[v] = n
      end
      v
    end

    #
    #
    #
    def pop
      k = @tail.prev_node.key
      n = @lookup.delete(k)
      node_delete(n) if n
    end

    #
    #
    #
    def push(v)
      if @lookup.has_key?(v)
        n = @lookup[v]
        node_delete(n)
        node_join(@tail.prev_node,n)
        node_join(n,@tail)
      else
        n = Node.new(v,v,@tail.prev_node,@tail)
        node_join(@tail.prev_node,n)
        node_join(n,@tail)
        @lookup[v] = n
      end
      v
    end

    alias :<< :push

    #
    # Produces an Array of key values.
    #
    # Returns [Array].
    #
    def queue
      r = []
      n = @head
      while (n = n.next_node) and n != @tail
        r << n.key
      end
      r
    end

    #
    # Converts to an Array of node values.
    #
    # Returns [Array].
    #
    def to_a
      r = []
      n = @head
      while (n = n.next_node) and n != @tail
        r << n.value
      end
      r
    end

    #
    # Number of nodes.
    #
    def length
      @lookup.length
    end

    alias size length

    #
    # Iterate over nodes, starting with the head node
    # and ending with the tail node.
    #
    def each
      n = @head
      while (n = n.next_node) and n != @tail
        yield(n.key,n.value)
      end
    end

  private

    #
    # Delete a node.
    #
    # n - A node.
    #
    def node_delete(n)
      node_join(n.prev_node,n.next_node)
      v = n.value
    end

    #
    # Purge a node.
    #
    # n - A node.
    #
    def node_purge(n)
      node_join(n.prev_node,n.next_node)
      v = n.value
      n.value = nil
      n.key = nil
      n.next_node = nil
      n.prev_node = nil
      v
    end

    # Join two nodes.
    #
    # a - A node.
    # b - A node.
    #
    def node_join(a,b)
      a.next_node = b
      b.prev_node = a
    end

  end

end
