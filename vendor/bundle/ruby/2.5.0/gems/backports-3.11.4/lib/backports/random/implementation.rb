require "backports/tools/arguments"
require "backports/random/MT19937"
require "backports/random/bits_and_bytes"

module Backports
  class Random
    # Implementation corresponding to the actual Random class of Ruby
    # The actual random generator (mersenne twister) is in MT19937.
    # Ruby specific conversions are handled in bits_and_bytes.
    # The high level stuff (argument checking) is done here.
    #
    module Implementation
      attr_reader :seed

      def initialize(seed = 0)
        super()
        srand(seed)
      end

      def srand(new_seed = 0)
        new_seed = Backports.coerce_to_int(new_seed)
        old, @seed = @seed, new_seed.nonzero? || ::Random.new_seed
        @mt = MT19937[ @seed ]
        old
      end

      def rand(limit = Backports::Undefined)
        case limit
          when Backports::Undefined
            @mt.random_float
          when Float
            limit * @mt.random_float unless limit <= 0
          when Range
            _rand_range(limit)
          else
            limit = Backports.coerce_to_int(limit)
            @mt.random_integer(limit) unless limit <= 0
        end || raise(ArgumentError, "invalid argument #{limit}")
      end

      def bytes(nb)
        nb = Backports.coerce_to_int(nb)
        raise ArgumentError, "negative size" if nb < 0
        @mt.random_bytes(nb)
      end

      def ==(other)
        other.is_a?(::Random) &&
          seed == other.seed &&
          left == other.send(:left) &&
          state == other.send(:state)
      end

      def marshal_dump
        @mt.marshal_dump << @seed
      end

      def marshal_load(ary)
        @seed = ary.pop
        @mt = MT19937.allocate
        @mt.marshal_load(ary)
      end

    private
      def state
        @mt.state_as_bignum
      end

      def left
        @mt.left
      end

      def _rand_range(limit)
        range = limit.end - limit.begin
        if (!range.is_a?(Float)) && range.respond_to?(:to_int) && range = Backports.coerce_to_int(range)
          range += 1 unless limit.exclude_end?
          limit.begin + @mt.random_integer(range) unless range <= 0
        elsif range = Backports.coerce_to(range, Float, :to_f)
          if range < 0
            nil
          elsif limit.exclude_end?
            limit.begin + @mt.random_float * range unless range <= 0
          else
            # cheat a bit... this will reduce the nb of random bits
            loop do
              r = @mt.random_float * range * 1.0001
              break limit.begin + r unless r > range
            end
          end
        end
      end
    end
  end
end
