unless Array.method_defined? :bsearch
  class Array
    def bsearch
      return to_enum(__method__) unless block_given?
      from = 0
      to   = size - 1
      satisfied = nil
      while from <= to do
        midpoint = (from + to).div(2)
        result = yield(cur = self[midpoint])
        case result
        when Numeric
          return cur if result == 0
          result = result < 0
        when true
          satisfied = cur
        when nil, false
          # nothing to do
        else
          raise TypeError, "wrong argument type #{result.class} (must be numeric, true, false or nil)"
        end

        if result
          to = midpoint - 1
        else
          from = midpoint + 1
        end
      end
      satisfied
    end
  end
end
