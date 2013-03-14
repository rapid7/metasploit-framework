require 'json'

require 'iconv'
ISO_8859_1_TO_UTF8 = Iconv.new('utf-8', 'iso-8859-15')
class ::String
  def to_utf8
    ISO_8859_1_TO_UTF8.iconv self
  end
end

class Fuzzer
  def initialize(n, freqs = {})
    sum = freqs.inject(0.0) { |s, x| s + x.last }
    freqs.each_key { |x| freqs[x] /= sum }
    s = 0.0
    freqs.each_key do |x|
      freqs[x] = s .. (s + t = freqs[x])
      s += t
    end
    @freqs = freqs
    @n = n
    @alpha = (0..0xff).to_a
  end

  def random_string
    s = ''
    30.times { s << @alpha[rand(@alpha.size)] }
    s.to_utf8
  end

  def pick
    r = rand
    found = @freqs.find { |k, f| f.include? rand }
    found && found.first
  end

  def make_pick
    k = pick
    case
    when k == Hash, k == Array
      k.new
    when k == true, k == false, k == nil
      k
    when k == String
      random_string
    when k == Fixnum
      rand(2 ** 30) - 2 ** 29
    when k == Bignum
      rand(2 ** 70) - 2 ** 69
    end
  end

  def fuzz(current = nil)
    if @n > 0
      case current
      when nil
        @n -= 1
        current = fuzz [ Hash, Array ][rand(2)].new
      when Array
        while @n > 0
          @n -= 1
          current << case p = make_pick
          when Array, Hash
            fuzz(p)
          else
            p
          end
        end
      when Hash
        while @n > 0
          @n -= 1
          current[random_string] = case p = make_pick
          when Array, Hash
            fuzz(p)
          else
            p
          end
        end
      end
    end
    current
  end
end

class MyState < JSON.state
  WS = " \r\t\n"

  def initialize
    super(
          :indent       => make_spaces,
          :space        => make_spaces,
          :space_before => make_spaces,
          :object_nl    => make_spaces,
          :array_nl     => make_spaces,
          :max_nesting  => false
         )
  end

  def make_spaces
    s = ''
    rand(1).times { s << WS[rand(WS.size)] }
    s
  end
end

n = (ARGV.shift || 500).to_i
loop do
  fuzzer = Fuzzer.new(n,
                      Hash => 25,
                      Array => 25,
                      String => 10,
                      Fixnum => 10,
                      Bignum => 10,
                      nil => 5,
                      true => 5,
                      false => 5
                     )
  o1 = fuzzer.fuzz
  json = JSON.generate o1, MyState.new
  if $DEBUG
    puts "-" * 80
    puts json, json.size
  else
    puts json.size
  end
  begin
    o2 = JSON.parse(json, :max_nesting => false)
  rescue JSON::ParserError => e
    puts "Caught #{e.class}: #{e.message}\n#{e.backtrace * "\n"}"
    puts "o1 = #{o1.inspect}", "json = #{json}", "json_str = #{json.inspect}"
    puts "locals = #{local_variables.inspect}"
    exit
  end
  if o1 != o2
    puts "mismatch", "o1 = #{o1.inspect}", "o2 = #{o2.inspect}",
      "json = #{json}", "json_str = #{json.inspect}"
    puts "locals = #{local_variables.inspect}"
  end
end
