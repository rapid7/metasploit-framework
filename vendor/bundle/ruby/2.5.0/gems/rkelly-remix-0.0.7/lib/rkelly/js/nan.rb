module RKelly
  module JS
    # Class to represent Not A Number
    # In Ruby NaN != NaN, but in JS, NaN == NaN
    class NaN < ::Numeric
      def ==(other)
        other.respond_to?(:nan?) && other.nan?
      end

      def nan?
        true
      end

      def +(o); self; end
      def -(o); self; end
    end
  end
end
