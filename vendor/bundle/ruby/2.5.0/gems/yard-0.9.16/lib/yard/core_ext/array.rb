# frozen_string_literal: true
class Array
  # Places values before or after another object (by value) in
  # an array. This is used in tandem with the before and after
  # methods of the {Insertion} class.
  #
  # @example Places an item before another
  #   [1, 2, 3].place(4).before(3) # => [1, 2, 4, 3]
  # @example Places an item after another
  #   [:a, :b, :c].place(:x).after(:a) # => [:a, :x, :b, :c]
  # @param [Array] values value to insert
  # @return [Insertion] an insertion object to
  # @see Insertion#before
  # @see Insertion#after
  def place(*values) Insertion.new(self, values) end
end
