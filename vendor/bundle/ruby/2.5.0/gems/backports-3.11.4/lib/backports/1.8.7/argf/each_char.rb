unless ARGF.respond_to? :each_char
  require 'backports/tools/alias_method'
  require 'enumerator'

  class << ARGF
    def each_char
      return to_enum(:each_char) unless block_given?
      if $KCODE == "UTF-8"
        lookup = 7.downto(4)
        while c = read(1) do
          n = c[0]
          leftmost_zero_bit = lookup.find{|i| n[i].zero? }
          case leftmost_zero_bit
          when 7 # ASCII
            yield c
          when 6 # UTF 8 complementary characters
            next # Encoding error, ignore
          else
            more = read(6-leftmost_zero_bit)
            break unless more
            yield c+more
          end
        end
      else
        while s = read(1)
          yield s
        end
      end

      self
    end

    Backports.alias_method self, :chars, :each_char
  end
end
