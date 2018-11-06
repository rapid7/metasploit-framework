module Backports
  class Random
    # Supplement the MT19937 class with methods to do
    # conversions the same way as MRI.
    # No argument checking is done here either.

    class MT19937
      FLOAT_FACTOR = 1.0/9007199254740992.0
      # generates a random number on [0,1) with 53-bit resolution
      def random_float
        ((random_32_bits >> 5) * 67108864.0 + (random_32_bits >> 6)) * FLOAT_FACTOR;
      end

      # Returns an integer within 0...upto
      def random_integer(upto)
        n = upto - 1
        nb_full_32 = 0
        while n > PAD_32_BITS
          n >>= 32
          nb_full_32 += 1
        end
        mask = mask_32_bits(n)
        begin
          rand = random_32_bits & mask
          nb_full_32.times do
            rand <<= 32
            rand |= random_32_bits
          end
        end until rand < upto
        rand
      end

      def random_bytes(nb)
        nb_32_bits = (nb + 3) / 4
        random = nb_32_bits.times.map { random_32_bits }
        random.pack("L" * nb_32_bits)[0, nb]
      end

      def state_as_bignum
        b = 0
        @state.each_with_index do |val, i|
          b |= val << (32 * i)
        end
        b
      end

      def left # It's actually the number of words left + 1, as per MRI...
        MT19937::STATE_SIZE - @last_read
      end

      def marshal_dump
        [state_as_bignum, left]
      end

      def marshal_load(ary)
        b, left = ary
        @last_read = MT19937::STATE_SIZE - left
        @state = Array.new(STATE_SIZE)
        STATE_SIZE.times do |i|
          @state[i] = b & PAD_32_BITS
          b >>= 32
        end
      end

      # Convert an Integer seed of arbitrary size to either a single 32 bit integer, or an Array of 32 bit integers
      def self.convert_seed(seed)
        seed = seed.abs
        long_values = []
        begin
          long_values << (seed & PAD_32_BITS)
          seed >>= 32
        end until seed == 0

        long_values.pop if long_values[-1] == 1 && long_values.size > 1 # Done to allow any kind of sequence of integers

        long_values.size > 1 ? long_values : long_values.first
      end

      def self.[](seed)
        new(convert_seed(seed))
      end

    private
      MASK_BY = [1,2,4,8,16]
      def mask_32_bits(n)
        MASK_BY.each do |shift|
          n |= n >> shift
        end
        n
      end
    end
  end
end
