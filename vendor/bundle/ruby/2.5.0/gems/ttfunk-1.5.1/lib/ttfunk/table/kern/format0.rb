require_relative '../../reader'

module TTFunk
  class Table
    class Kern
      class Format0
        include Reader

        attr_reader :attributes
        attr_reader :pairs

        def initialize(attributes = {})
          @attributes = attributes

          num_pairs, *pairs = attributes.delete(:data).unpack('nx6n*')

          @pairs = {}
          num_pairs.times do |i|
            # sanity check, in case there's a bad length somewhere
            break if i * 3 + 2 > pairs.length
            left = pairs[i * 3]
            right = pairs[i * 3 + 1]
            value = to_signed(pairs[i * 3 + 2])
            @pairs[[left, right]] = value
          end
        end

        def vertical?
          @attributes[:vertical]
        end

        def horizontal?
          !vertical?
        end

        def cross_stream?
          @attributes[:cross]
        end

        def recode(mapping)
          subset = []
          pairs.each do |(left, right), value|
            if mapping[left] && mapping[right]
              subset << [mapping[left], mapping[right], value]
            end
          end

          return nil if subset.empty?

          num_pairs = subset.length
          search_range = 2 * 2**(Math.log(num_pairs) / Math.log(2)).to_i
          entry_selector = (Math.log(search_range / 2) / Math.log(2)).to_i
          range_shift = (2 * num_pairs) - search_range

          [
            attributes[:version],
            num_pairs * 6 + 14,
            attributes[:coverage],
            num_pairs,
            search_range,
            entry_selector,
            range_shift,
            subset
          ].flatten.pack('n*')
        end
      end
    end
  end
end
