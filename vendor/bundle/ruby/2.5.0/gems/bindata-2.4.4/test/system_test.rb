#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe "lambdas with index" do
  class NestedLambdaWithIndex < BinData::Record
    uint8 :a, value: -> { index * 10 }
  end

  it "uses index of containing array" do
    arr = BinData::Array.new(type:
                               [:uint8, { value: -> { index * 10 } }],
                             initial_length: 3)
    arr.snapshot.must_equal [0, 10, 20]
  end

  it "uses index of nearest containing array" do
    arr = BinData::Array.new(type: :nested_lambda_with_index,
                             initial_length: 3)
    arr.snapshot.must_equal [{a: 0}, {a: 10}, {a: 20}]
  end

  it "fails if there is no containing array" do
    obj = NestedLambdaWithIndex.new
    lambda { obj.a.to_s }.must_raise NoMethodError
  end
end

describe "lambdas with parent" do
  it "accesses immediate parent when no parent is specified" do
    class NestedLambdaWithoutParent < BinData::Record
      int8 :a, value: 5
      int8 :b, value: -> { a }
    end

    class TestLambdaWithoutParent < BinData::Record
      int8   :a, value: 3
      nested_lambda_without_parent :x
    end

    obj = TestLambdaWithoutParent.new
    obj.x.b.must_equal 5
  end

  it "accesses parent's parent when parent is specified" do
    class NestedLambdaWithParent < BinData::Record
      int8 :a, value: 5
      int8 :b, value: -> { parent.a }
    end

    class TestLambdaWithParent < BinData::Record
      int8   :a, value: 3
      nested_lambda_with_parent :x
    end

    obj = TestLambdaWithParent.new
    obj.x.b.must_equal 3
  end
end

describe BinData::Record, "with choice field" do
  class TupleRecord < BinData::Record
    uint8 :a, value: 3
    uint8 :b, value: 5
  end

  class RecordWithChoiceField < BinData::Record
    choice :x, selection: 0 do
      tuple_record
    end
  end

  class RecordWithNestedChoiceField < BinData::Record
    uint8  :sel, value: 0
    choice :x, selection: 0 do
      choice selection: :sel do
        tuple_record
      end
    end
  end

  it "treats choice object transparently " do
    obj = RecordWithChoiceField.new

    obj.x.a.must_equal 3
  end

  it "treats nested choice object transparently " do
    obj = RecordWithNestedChoiceField.new

    obj.x.a.must_equal 3
  end

  it "has correct offset" do
    obj = RecordWithNestedChoiceField.new
    obj.x.b.abs_offset.must_equal 2
  end
end

describe BinData::Record, "containing bitfields" do
  class BCD < BinData::Primitive
    bit4 :d1
    bit4 :d2
    bit4 :d3

    def set(v)
      self.d1 = (v / 100) % 10
      self.d2 = (v /  10) % 10
      self.d3 =  v        % 10
    end

    def get()
      d1 * 100 + d2 * 10 + d3
    end
  end

  class BitfieldRecord < BinData::Record
    struct :a do
      bit4 :w
    end

    array  :b, type: :bit1, initial_length: 9

    struct :c do
      bit2 :x
    end

    bcd    :d
    bit6   :e
  end

  let(:obj) { BitfieldRecord.new }

  it "has correct num_bytes" do
    obj.num_bytes.must_equal 5
  end

  it "reads across bitfield boundaries" do
    obj.read [0b0111_0010, 0b0110_0101, 0b0010_1010, 0b1000_0101, 0b1000_0000].pack("CCCCC")

    obj.a.w.must_equal 7
    obj.b.must_equal [0, 0, 1, 0, 0, 1, 1, 0, 0]
    obj.c.x.must_equal 2
    obj.d.must_equal 954
    obj.e.must_equal 11
  end

  it "writes across bitfield boundaries" do
    obj.a.w = 3
    obj.b[2] = 1
    obj.b[5] = 1
    obj.c.x = 1
    obj.d = 850
    obj.e = 35
    obj.to_binary_s.must_equal_binary [0b0011_0010, 0b0100_0011, 0b0000_1010, 0b0001_0001, 0b1000_0000].pack("CCCCC")
  end
end

describe "Objects with debug_name" do
  it "haves default name of obj" do
    el = BinData::Uint8.new
    el.debug_name.must_equal "obj"
  end

  it "includes array index" do
    arr = BinData::Array.new(type: :uint8, initial_length: 2)
    arr[2].debug_name.must_equal "obj[2]"
  end

  it "includes field name" do
    s = BinData::Struct.new(fields: [[:uint8, :a]])
    s.a.debug_name.must_equal "obj.a"
  end

  it "delegates to choice" do
    choice_params = {choices: [:uint8], selection: 0}
    s = BinData::Struct.new(fields: [[:choice, :a, choice_params]])
    s.a.debug_name.must_equal "obj.a"
  end

  it "nests" do
    nested_struct_params = {fields: [[:uint8, :c]]}
    struct_params = {fields: [[:struct, :b, nested_struct_params]]}
    s = BinData::Struct.new(fields: [[:struct, :a, struct_params]])
    s.a.b.c.debug_name.must_equal "obj.a.b.c"
  end
end

describe "Tracing"  do
  it "should trace arrays" do
    arr = BinData::Array.new(type: :int8, initial_length: 5)

    io = StringIO.new
    BinData::trace_reading(io) { arr.read("\x01\x02\x03\x04\x05") }

    expected = (0..4).collect { |i| "obj[#{i}] => #{i + 1}\n" }.join("")
    io.value.must_equal expected
  end

  it "traces custom single values" do
    class DebugNamePrimitive < BinData::Primitive
      int8 :ex
      def get;     self.ex; end
      def set(val) self.ex = val; end
    end

    obj = DebugNamePrimitive.new

    io = StringIO.new
    BinData::trace_reading(io) { obj.read("\x01") }

    io.value.must_equal ["obj-internal-.ex => 1\n", "obj => 1\n"].join("")
  end

  it "traces choice selection" do
    obj = BinData::Choice.new(choices: [:int8, :int16be], selection: 0)

    io = StringIO.new
    BinData::trace_reading(io) { obj.read("\x01") }

    io.value.must_equal ["obj-selection- => 0\n", "obj => 1\n"].join("")
  end

  it "trims long trace values" do
    obj = BinData::String.new(read_length: 40)

    io = StringIO.new
    BinData::trace_reading(io) { obj.read("0000000000111111111122222222223333333333") }

    io.value.must_equal "obj => \"000000000011111111112222222222...\n"
  end
end

describe "Forward referencing with Primitive" do
  class FRPrimitive < BinData::Record
    uint8  :len, value: -> { data.length }
    string :data, read_length: :len
  end

  let(:obj) { FRPrimitive.new }

  it "initialises" do
    obj.snapshot.must_equal({len: 0, data: ""})
  end

  it "reads" do
    obj.read("\x04test")
    obj.snapshot.must_equal({len: 4, data: "test"})
  end

  it "sets value" do
    obj.data = "hello"
    obj.snapshot.must_equal({len: 5, data: "hello"})
  end
end

describe "Forward referencing with Array" do
  class FRArray < BinData::Record
    uint8  :len, value: -> { data.length }
    array :data, type: :uint8, initial_length: :len
  end

  let(:obj) { FRArray.new }

  it "initialises" do
    obj.snapshot.must_equal({len: 0, data: []})
  end

  it "reads" do
    obj.read("\x04\x01\x02\x03\x04")
    obj.snapshot.must_equal({len: 4, data: [1, 2, 3, 4]})
  end

  it "sets value" do
    obj.data = [1, 2, 3]
    obj.snapshot.must_equal({len: 3, data: [1, 2, 3]})
  end
end

describe "Evaluating custom parameters" do
  class CustomParameterRecord < BinData::Record
    mandatory_parameter :zz

    uint8 :a, value: :zz
    uint8 :b, value: :a
    uint8 :c, custom: :b
  end

  it "recursively evaluates parameter" do
    obj = CustomParameterRecord.new(zz: 5)
    obj.c.eval_parameter(:custom).must_equal 5
  end
end

describe BinData::Record, "with custom sized integers" do
  class CustomIntRecord < BinData::Record
    int40be :a
  end

  it "reads as expected" do
    str = "\x00\x00\x00\x00\x05"
    CustomIntRecord.read(str).snapshot.must_equal({a: 5})
  end
end

describe BinData::Record, "with choice field" do
  class ChoiceFieldRecord < BinData::Record
    int8 :a
    choice :b, selection: :a do
      struct 1, fields: [[:int8, :v]]
    end
  end

  it "assigns" do
    obj = BinData::Array.new(type: :choice_field_record)
    data = ChoiceFieldRecord.new(a: 1, b: {v: 3})
    obj.assign([data])
  end
end

describe BinData::Primitive, "representing a string" do
  class PascalStringPrimitive < BinData::Primitive
    uint8  :len,  value: -> { data.length }
    string :data, read_length: :len

    def get;   self.data; end
    def set(v) self.data = v; end
  end

  let(:obj) { PascalStringPrimitive.new("testing") }

  it "compares to regexp" do
    (obj =~ /es/).must_equal 1
  end

  it "compares to regexp" do
    (/es/ =~ obj).must_equal 1
  end
end

describe BinData::Record, "with boolean parameters" do
  class BooleanParameterRecord < BinData::Record
    default_parameter flag: true

    int8 :a, value: -> { flag ? 2 : 3 }
  end

  it "uses default parameter" do
    obj = BooleanParameterRecord.new
    obj.a.must_equal 2
  end

  it "overrides parameter" do
    obj = BooleanParameterRecord.new(flag: false)
    obj.a.must_equal 3
  end

  it "overrides parameter with same value" do
    obj = BooleanParameterRecord.new(flag: true)
    obj.a.must_equal 2
  end
end
