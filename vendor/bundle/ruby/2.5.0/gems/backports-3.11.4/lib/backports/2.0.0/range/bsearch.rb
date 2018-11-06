unless Range.method_defined? :bsearch
  require 'backports/tools/float_integer_conversion'

  class Range
    def bsearch
      return to_enum(:bsearch) unless block_given?
      from = self.begin
      to   = self.end
      unless from.is_a?(Numeric) && to.is_a?(Numeric)
        raise TypeError, "can't do binary search for #{from.class}"
      end

      midpoint = nil
      if from.is_a?(Integer) && to.is_a?(Integer)
        convert = Proc.new{ midpoint }
      else
        from = Backports.float_to_integer(from.to_f)
        to   = Backports.float_to_integer(to.to_f)
        convert = Proc.new{ Backport.integer_to_float(midpoint) }
      end
      to -= 1 if exclude_end?
      satisfied = nil
      while from <= to do
        midpoint = (from + to).div(2)
        result = yield(cur = convert.call)
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
