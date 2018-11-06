require 'minitest/autorun'
require 'bit-struct'

class Test_BitStruct < Minitest::Test

  class T1 < BitStruct
    unsigned    :foo, 8
  end

  class T2 < BitStruct
    unsigned    :bar, 8
  end

  class Rest < BitStruct
    unsigned    :zap, 8
    rest        :body, T2
  end

  class NestedPart < BitStruct
    unsigned :x,    5
    unsigned :y,    3, :default => 2
    char     :s,  5*8
  end

  class Container < BitStruct
    nest    :n1,  NestedPart, :default => NestedPart.new(:x=>1, :s=>"deflt")
    nest    :n2,  NestedPart
  end

  class Overflow < BitStruct
    unsigned    :f1,    3
    unsigned    :f2,    5
    unsigned    :f3,    8
    unsigned    :f4,    16
    unsigned    :f5,    32
    char        :f6,    24
    unsigned    :f7,    8
  end

  class BS < BitStruct
    def self.next_name
      (@@next_name ||= "f000").succ!.dup
    end

    unsigned    next_name, 13
    unsigned    next_name, 6
    signed      next_name, 5

    char        next_name, 16

    unsigned    next_name, 2
    signed      next_name, 3,   :default => -2
    unsigned    next_name, 3

    unsigned f1=next_name, 16

    signed      next_name,  8
    signed      next_name, 16,  :endian => :little
    signed      next_name, 16,  :endian => :native
    signed   f2=next_name, 32
    unsigned    next_name, 56,  :endian => :big
    signed      next_name, 48,  :endian => :little

    char        next_name, 8,   :default => "b"
    float       next_name, 32,  :default => 1.23
    float       next_name, 64,  :format => "%10.5f"

    octets      next_name, 32,  :default => "192.168.1.123"

    hex_octets  next_name, 48,  :default => "ab:cd:ef:01:23:45"

    unsigned    next_name, 1
    unsigned    next_name, 11,  :fixed => 100  # unaligned!
    signed      next_name, 7                   # unaligned!
    signed      next_name, 14                  # unaligned and touches 3 bytes
    signed      next_name, 7,   :fixed => 1000 # unaligned!

    char        next_name, 24

    rest        :bs_body

    INITIAL_VALUES = {
      f1 => 1234,
      f2 => 5678
    }

    INITIAL_VALUES.each do |f, v|
      initial_value.send "#{f}=", v
    end

  end

  class BS_1 < BS

    signed      next_name, 4,   :fixed => 25
    unsigned    next_name, 3,   :fixed => 0.01
    unsigned    next_name, 1

    unsigned    next_name, 32,  :fixed => 1000

    char        next_name, 40
    text        next_name, 40

    unsigned    next_name, 8,   :default => 0xEF

    unsigned    next_name, 8

    unsigned    next_name, 1

    rest        :bs1_body

  end

  def setup
    srand(767343)
    @bs = BS.new
    @bs_1 = BS_1.new
    @simple = [T1.new, T2.new]
    @testers = @simple + [@bs, @bs_1]
  end

  def test_init
    @testers.each do |bs|
      if defined?(bs.class::INITIAL_VALUES)
        initial_values = bs.class::INITIAL_VALUES
      end
      bs.fields.each do |field|
        iv = initial_values && initial_values[field.name]
        iv ||= field.default

        if iv
          case field
          when BitStruct::FloatField
            assert_in_delta(iv, bs.send(field.name), 100,
              "In #{field.name} of a #{bs.class}")
          else
            assert_equal(iv, bs.send(field.name),
              "In #{field.name} of a #{bs.class}")
          end
        end
      end
    end
  end

  def test_init_with_value
    randomize(@bs_1)

    b = BS_1.new(@bs_1)
    assert_equal(@bs_1, b, "Initialize with argument failed.")

    c = BS_1.new(b)
    assert_equal(@bs_1, c, "Initialize with argument failed.")

    b1 = BS_1.new("")
    b2 = BS_1.new(nil)
    assert_equal(b1, b2, "Initialize with short argument failed.")
  end

  def test_init_with_hash
    randomize(@bs_1)

    h = {}
    @bs_1.fields.each do |f|
      h[f.name] = @bs_1.send(f.name)
    end

    b = BS_1.new(h)
    assert_equal(@bs_1, b, "Initialize with argument failed.")
  end

  def test_join
    assert_equal(@bs+@bs_1, BitStruct.join(@bs,@bs_1))
    assert_equal(@bs+@bs_1, [@bs,@bs_1].join(""))
  end

  def test_parse
    orig = @testers
    orig.each do |bs|
      randomize(bs)
    end

    data = BitStruct.join(orig)
    round_trip = BitStruct.parse(data, orig.map{|bs|bs.class})
    orig.zip(round_trip) do |bs1, bs2|
      assert_equal(bs1, bs2)
    end
  end

  def test_closed
    assert_raises(BitStruct::ClosedClassError) do
      BS.class_eval do
        unsigned :foo, 3
      end
    end
  end

  def test_rest
    len0 = @bs_1.length

    @bs_1.bs1_body = "a"*50
    assert_equal("a"*50, @bs_1.bs1_body)
    assert_equal(len0+50, @bs_1.length)

    @bs_1.bs1_body = "b"*60
    assert_equal("b"*60, @bs_1.bs1_body)
    assert_equal(len0+60, @bs_1.length)

    @bs_1.bs1_body = "c"*40
    assert_equal("c"*40, @bs_1.bs1_body)
    assert_equal(len0+40, @bs_1.length)

    @bs_1.bs1_body = ""
    assert_equal("", @bs_1.bs1_body)
    assert_equal(len0, @bs_1.length)
  end

  def test_rest_with_class
    r = Rest.new
    t2 = T2.new
    t2.bar = 123
    r.body = t2
    assert_equal(123, r.body.bar)
  end

  def test_rest_with_class_constructed
    r = Rest.new(['0011'].pack('H*'))
    assert_equal(0x00, r.zap)
    assert_equal(0x11, r.body.bar)
  end

  def test_nest
    cont = Container.new
    n1 = cont.n1

    assert_equal(1, n1.x)
    assert_equal(2, n1.y)
    assert_equal("deflt", n1.s)

    n1.sub(/./, " ")

    assert_equal(1, n1.x)
    assert_equal(2, n1.y)
    assert_equal("deflt", n1.s)

    n1 = cont.n1
    n2 = cont.n2

    assert_equal(0, n2.x)
    assert_equal(2, n2.y)
    assert_equal("\0"*5, n2.s)

    n = NestedPart.new(:x=>4, :y=>1, :s=>"qwert")
    cont.n1 = n

    assert_equal(4, cont.n1.x)
    assert_equal(1, cont.n1.y)
    assert_equal("qwert", cont.n1.s)

    assert_raises(ArgumentError) {cont.n2 = Container.new}
  end

  def test_overflow
    ov = Overflow.new
    empty = ov.dup

    ov.fields.each do |field|
      ov.gsub(/./, "\0")

      case field
      when BitStruct::CharField
        val1 = "a" * (field.length+5)
        val2 = ""

      when BitStruct::UnsignedField
        val1 = 2**32 - 5**10 # mixed bit pattern
        val2 = 0
      end

      ov.send("#{field.name}=", val1)
      ov.send("#{field.name}=", val2)

      assert_equal(empty, ov)
    end
  end

  def test_access
    repeat_access_test(@bs, 10)
  end

  def test_inheritance
    assert_equal(@bs.fields.size, @bs_1.fields.size - BS_1.own_fields.size,
      "Wrong number of fields inherited in BS_1.")

    repeat_access_test(@bs_1, 10)
  end

  def test_initial_value
    bs = @bs
    bs.class::INITIAL_VALUES.each do |f,v|
      assert_equal(v, bs.send(f), "In #{f} of a #{bs.class}")
    end
  end

  def test_inherited_initial_value
    bs = @bs_1
    bs.class::INITIAL_VALUES.each do |f,v|
      assert_equal(v, bs.send(f), "In #{f} of a #{bs.class}")
    end
  end

  def test_to_h
    h = @bs_1.to_h(:convert_keys => :to_s)
    field_names = @bs_1.fields.map{|f|f.name.to_s}
    assert_equal(field_names.sort, h.keys.sort)
    field_names.each do |name|
      assert_equal(@bs_1.send(name), h[name])
    end
  end

  def test_to_a_exclude_rest
    include_rest = false
    a = @bs_1.to_a(include_rest)
    field_names = @bs_1.fields.map{|f|f.name.to_s}
    assert_equal(a.size, field_names.size)
    field_names.each_with_index do |name, i|
      assert_equal(@bs_1.send(name), a[i])
    end
  end

  def test_to_a
    include_rest = true
    a = @bs_1.to_a(include_rest)
    field_names = @bs_1.fields.map{|f|f.name.to_s}
    field_names << @bs_1.rest_field.name
    assert_equal(a.size, field_names.size)
    field_names.each_with_index do |name, i|
      assert_equal(@bs_1.send(name), a[i])
    end
  end

  def test_format_option
    formatted_fields = @bs.fields.select {|f|f.format}
    formatted_fields.each do |f|
      val = @bs.send(f.name)
      assert_equal(f.format % val, f.inspect_in_object(@bs, {}))
    end
  end

  def test_yaml
    assert_equal(@bs_1, YAML.load(@bs_1.to_yaml))
  end

  def test_field_by_name
    name = :f007
    f = @bs.field_by_name(name)
    assert(f)
    assert_equal(f.name, name)
  end

  #--------
  def repeat_access_test(bs, n)
    last_set_value = {}

    start_length = bs.length

    n.times do
      bs.fields.each do |field|
        last_set_value[field] = randomize_field(bs, field)

        bs.fields.each do |f2|
          lsv2 = last_set_value[f2]
          if lsv2
            case f2
            when BitStruct::FloatField
              assert_in_delta(lsv2, bs.send(f2.name), 100)
            else
              begin
                assert_equal(lsv2, bs.send(f2.name))
              rescue Test::Unit::AssertionFailedError => ex
                msg =
                  "In #{f2.inspect} after setting #{field.inspect} to" +
                  " #{last_set_value[field].inspect}"
                raise ex, msg + "\n" + ex.message, ex.backtrace
              end
            end
          end
        end
      end
    end

    finish_length = bs.length

    assert_equal(start_length, finish_length, "Length differs after test!")
  end

  def randomize(bs)
    bs.fields.each do |f|
      randomize_field(bs, f)
    end
  end

  def randomize_field(bs, field)
    case field
    when BitStruct::SignedField
      divisor = field.options[:fixed]
      if divisor
        value = (rand(2**field.size) - 2**(field.size-1))/divisor.to_f
      else
        value = rand(2**field.size) - 2**(field.size-1)
      end
      bs.send "#{field.name}=", value
      last_set_value = value

    when BitStruct::UnsignedField
      divisor = field.options[:fixed]
      if divisor
        value = rand(2**field.size)/divisor.to_f
      else
        value = rand(2**field.size)
        ## should ensure that there are some very low and very high walues
        ## esp. 0, 1, 2**n - 1, and so on
      end
      bs.send "#{field.name}=", value
      last_set_value = value

    when BitStruct::HexOctetField
      val = (1..field.length/8).map {"%02x" % rand(256)}.join(":")
      bs.send "#{field.name}=", val
      last_set_value = val

    when BitStruct::OctetField
      val = (1..field.length/8).map {"%d" % rand(256)}.join(".")
      bs.send "#{field.name}=", val
      last_set_value = val

    when BitStruct::CharField
      s = (rand(64)+32).chr
      value = s * (field.length/8)
      bs.send "#{field.name}=", value
      last_set_value = value

    when BitStruct::TextField
      s = (rand(64)+32).chr
      value = s * rand(field.length*2/8)
      bs.send "#{field.name}=", value
      last_set_value = s * [field.length/8, value.length].min

    when BitStruct::FloatField
      value = rand(2**30)
      bs.send "#{field.name}=", value
      last_set_value = value

    else raise
    end

    return last_set_value
  end
end
