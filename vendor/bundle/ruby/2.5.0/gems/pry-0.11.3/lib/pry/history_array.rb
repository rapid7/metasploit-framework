class Pry
  # A history array is an array to which you can only add elements. Older
  # entries are removed progressively, so that the array never contains more than
  # N elements.
  #
  # History arrays are used by Pry to store the output of the last commands.
  #
  # @example
  #   ary = Pry::HistoryArray.new 10
  #   ary << 1 << 2 << 3
  #   ary[0] # => 1
  #   ary[1] # => 2
  #   10.times { |n| ary << n }
  #   ary[0] # => nil
  #   ary[-1] # => 9
  class HistoryArray
    include Enumerable

    # @param [Integer] size Maximum amount of objects in the array
    def initialize(size)
      @max_size = size

      @hash  = {}
      @count = 0
    end

    # Pushes an object at the end of the array
    # @param [Object] value Object to be added
    def <<(value)
      @hash[@count] = value

      if @hash.size > max_size
        @hash.delete(@count - max_size)
      end

      @count += 1

      self
    end

    # @overload [](index)
    #   @param [Integer] index Index of the item to access.
    #   @return [Object, nil] Item at that index or nil if it has been removed.
    # @overload [](index, size)
    #   @param [Integer] index Index of the first item to access.
    #   @param [Integer] size Amount of items to access
    #   @return [Array, nil] The selected items. Nil if index is greater than
    #     the size of the array.
    # @overload [](range)
    #   @param [Range<Integer>] range Range of indices to access.
    #   @return [Array, nil] The selected items. Nil if index is greater than
    #     the size of the array.
    def [](index_or_range, size = nil)
      if index_or_range.is_a? Integer
        index = convert_index(index_or_range)

        if size
          end_index = index + size
          index > @count ? nil : (index...[end_index, @count].min).map do |n|
            @hash[n]
          end
        else
          @hash[index]
        end
      else
        range = convert_range(index_or_range)
        range.begin > @count ? nil : range.map { |n| @hash[n] }
      end
    end

    # @return [Integer] Amount of objects in the array
    def size
      @count
    end
    alias count size
    alias length size

    def empty?
      size == 0
    end

    def each
      ((@count - size)...@count).each do |n|
        yield @hash[n]
      end
    end

    def to_a
      ((@count - size)...@count).map { |n| @hash[n] }
    end

    # @return [Hash] copy of the internal @hash history
    def to_h
      @hash.dup
    end

    def pop!
      @hash.delete @count - 1
      @count -= 1
    end

    def inspect
      "#<#{self.class} size=#{size} first=#{@count - size} max_size=#{max_size}>"
    end

    # @return [Integer] Maximum amount of objects in the array
    attr_reader :max_size

    private
    def convert_index(n)
      n >= 0 ? n : @count + n
    end

    def convert_range(range)
      end_index = convert_index(range.end)
      end_index += 1 unless range.exclude_end?

      Range.new(convert_index(range.begin), [end_index, @count].min, true)
    end
  end
end
