module Backports
  class Random
    # An implementation of Mersenne Twister MT19937 in Ruby
    class MT19937
      STATE_SIZE = 624
      LAST_STATE = STATE_SIZE - 1
      PAD_32_BITS = 0xffffffff

      # See seed=
      def initialize(seed)
        self.seed = seed
      end

      LAST_31_BITS = 0x7fffffff
      OFFSET = 397

      # Generates a completely new state out of the previous one.
      def next_state
        STATE_SIZE.times do |i|
          mix = @state[i] & 0x80000000 | @state[i+1 - STATE_SIZE] & 0x7fffffff
          @state[i] = @state[i+OFFSET - STATE_SIZE] ^ (mix >> 1)
          @state[i] ^= 0x9908b0df if mix.odd?
        end
        @last_read = -1
      end

      # Seed must be either an Integer (only the first 32 bits will be used)
      # or an Array of Integers (of which only the first 32 bits will be used)
      #
      # No conversion or type checking is done at this level
      def seed=(seed)
        case seed
        when Integer
          @state = Array.new(STATE_SIZE)
          @state[0] = seed & PAD_32_BITS
          (1..LAST_STATE).each do |i|
            @state[i] = (1812433253 * (@state[i-1]  ^ @state[i-1]>>30) + i)& PAD_32_BITS
          end
          @last_read = LAST_STATE
        when Array
          self.seed = 19650218
          i=1
          j=0
          [STATE_SIZE, seed.size].max.times do
            @state[i] = (@state[i] ^ (@state[i-1] ^ @state[i-1]>>30) * 1664525) + j + seed[j] & PAD_32_BITS
            if (i+=1) >= STATE_SIZE
              @state[0] = @state[-1]
              i = 1
            end
            j = 0 if (j+=1) >= seed.size
          end
          (STATE_SIZE-1).times do
            @state[i] = (@state[i] ^ (@state[i-1] ^ @state[i-1]>>30) * 1566083941) - i & PAD_32_BITS
            if (i+=1) >= STATE_SIZE
              @state[0] = @state[-1]
              i = 1
            end
          end
          @state[0] = 0x80000000
        else
          raise ArgumentError, "Seed must be an Integer or an Array"
        end
      end

      # Returns a random Integer from the range 0 ... (1 << 32)
      def random_32_bits
        next_state if @last_read >= LAST_STATE
        @last_read += 1
        y = @state[@last_read]
        # Tempering
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
      end
    end
  end
end
