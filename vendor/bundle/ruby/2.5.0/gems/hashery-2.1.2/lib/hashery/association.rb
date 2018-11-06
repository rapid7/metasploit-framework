module Hashery

  # TODO: Should associations be singleton?
  #
  # TODO: Is it really wise to keep a table of all associations?

  # Association is a general binary association that allows one
  # object to be associated with another. It has a variety of uses,
  # such as linked-lists, simple ordered maps and mixed collections,
  # among them.
  #
  # NOTE: This class is still fairly experimental. And it is not
  # loaded along with the other Hashery libraries when using
  # `require 'hashery'`. It must be required independently.
  #
  # Associations can be used to draw simple relationships.
  #
  #   :Apple >> :Fruit
  #   :Apple >> :Red
  #
  #   :Apple.associations #=> [ :Fruit, :Red ]
  #
  # It can also be used for simple lists of ordered pairs.
  #
  #   c = [ :a >> 1, :b >> 2 ]
  #   c.each { |k,v| puts "#{k} associated with #{v} }
  #
  # produces
  #
  #   a associated with 1
  #   b associated with 2
  #
  # The method :>> is used to construct the association.
  # It is a rarely used method so it is generally available.
  # But you can't use it for any of the following classes
  # becuase they use #>> for other things.
  #
  #   Bignum
  #   Fixnum
  #   Date
  #   IPAddr
  #   Process::Status
  #
  class Association
    include Comparable

    class << self
      #
      # Store association references.
      #
      # Returns `Hash` of all associaitons.
      #
      def reference
        @reference ||= Hash.new{ |h,k,v| h[k]=[] }
      end

      #
      # Shortcut for #new.
      #
      # index - The "index key" of the association.
      # value - The "value" of the association.
      #
      # Returns `Association`.
      #
      def [](index, value)
        new(index, value)
      end

      #def new(index, value)
      #  lookup[[index, value]] ||= new(index, value)
      #end

      #def lookup
      #  @lookup ||= {}
      #end
    end

    #
    # The "index key" of the association.
    #
    attr_accessor :index

    #
    # The "value" of the association.
    #
    attr_accessor :value

    #
    # Initialize new Association.
    #
    # index - The "index key" of the association.
    # value - The "value" of the association.
    #
    def initialize(index, value=nil)
      @index = index
      @value = value

      unless index.associations.include?(value)
        index.associations << value
      end
    end

    #
    # Compare the values of two associations.
    #
    # TODO: Comparions with non-associations?
    #
    # assoc - The other `Association`.
    #
    # Returns [Integer] `1`, `0`, or `-1`.
    #
    def <=>(assoc)
      return -1 if self.value < assoc.value
      return  1 if self.value > assoc.value
      return  0 if self.value == assoc.value
    end

    #
    # Invert association, making the index the value and vice-versa.
    #
    # Returns [Array] with two-elements reversed.
    #
    def invert!
      temp = @index
      @index = @value
      @value = temp
    end

    #
    # Produce a string representation.
    #
    # Returns [String].
    #
    def to_s
      return "#{index} >> #{value}"
    end

    #
    # Produce a literal code string for creating an association.
    #
    # Returns [String].
    #
    def inspect
      "#{index.inspect} >> #{value.inspect}"
    end

    #
    # Convert to two-element associative array.
    #
    # Returns [Array] Two-element Array of index and value pair.
    #
    def to_ary
      [index, value]
    end

    #
    # Object extensions.
    #
    module Kernel

      #
      # Define an association for +self+.
      #
      # to - The value of the association.
      #
      # Returns [Association].
      #
      def >>(to)
        Association.new(self, to)
      end

      #
      # List of associations for this object.
      #
      # Returns an `Array` of `Associations`.
      #
      def associations
        Association.reference[self]
      end

    end

  end

end

class Object #:nodoc:
  include Hashery::Association::Kernel
end

#--
# Setup the >> method in classes that use it already.
#
# This is a bad idea b/c it can cause backward compability issues.
#
# class Bignum
#   alias_method( :rshift, :>>) if method_defined?(:>>)
#   remove_method :>>
# end
#
# class Fixnum
#   alias_method( :rshift, :>>) if method_defined?(:>>)
#   remove_method :>>
# end
#
# class Date
#   alias_method( :months_later, :>>) if method_defined?(:>>)
#   remove_method :>>
# end
#
# class IPAddr
#   alias_method( :rshift, :>>) if method_defined?(:>>)
#   remove_method :>>
# end
#
# class Process::Status
#   alias_method( :rshift, :>>) if method_defined?(:>>)
#   remove_method :>>
# end
#++

# Copyright (c) 2005 Rubyworks, Thomas Sawyer
