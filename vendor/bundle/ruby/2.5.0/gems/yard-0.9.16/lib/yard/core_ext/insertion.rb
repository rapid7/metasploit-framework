# frozen_string_literal: true
# The Insertion class inserts a value before or after another
# value in a list.
#
# @example
#   Insertion.new([1, 2, 3], 4).before(3) # => [1, 2, 4, 3]
class Insertion
  # Creates an insertion object on a list with a value to be
  # inserted. To finalize the insertion, call {#before} or
  # {#after} on the object.
  #
  # @param [Array] list the list to perform the insertion on
  # @param [Object] value the value to insert
  def initialize(list, value)
    @list = list
    @values = (Array === value ? value : [value])
  end

  # Inserts the value before +val+
  # @param [Object] val the object the value will be inserted before
  # @param [Boolean] recursive look inside sublists
  def before(val, recursive = false) insertion(val, 0, recursive) end

  # Inserts the value after +val+.
  #
  # @example If subsections are ignored
  #   Insertion.new([1, [2], 3], :X).after(1) # => [1, [2], :X, 3]
  # @param [Object] val the object the value will be inserted after
  # @param [Boolean] recursive look inside sublists
  def after(val, recursive = false) insertion(val, 1, recursive) end

  # Alias for {#before} with +recursive+ set to true
  # @since 0.6.0
  def before_any(val) insertion(val, 0, true) end

  # Alias for {#after} with +recursive+ set to true
  # @since 0.6.0
  def after_any(val) insertion(val, 1, true) end

  private

  # This method performs the actual insertion
  #
  # @param [Object] val the value to insert
  # @param [Fixnum] rel the relative index (0 or 1) of where the object
  #   should be placed
  # @param [Boolean] recursive look inside sublists
  # @param [Array] list the list to place objects into
  def insertion(val, rel, recursive = false, list = @list)
    if recursive
      list.each do |item|
        next unless item.is_a?(Array)
        tmp = item.dup
        insertion(val, rel, recursive, item)
        return(list) unless item == tmp
      end
    end

    index = list.index(val)
    list[index + rel, 0] = @values if index
    list
  end
end
