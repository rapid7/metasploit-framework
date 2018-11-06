#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Record do
  it "is not registered" do
    lambda {
      BinData::RegisteredClasses.lookup("Record")
    }.must_raise BinData::UnRegisteredTypeError
  end
end

describe BinData::Record, "when defining with errors" do
  it "fails on non registered types" do
    lambda {
      class BadTypeRecord < BinData::Record
        non_registered_type :a
      end
    }.must_raise_on_line TypeError, 2, "unknown type 'non_registered_type' in BadTypeRecord"
  end

  it "gives correct error message for non registered nested types" do
    lambda {
      class BadNestedTypeRecord < BinData::Record
        array :a, type: :non_registered_type
      end
    }.must_raise_on_line TypeError, 2, "unknown type 'non_registered_type' in BadNestedTypeRecord"
  end

  it "gives correct error message for non registered nested types in blocks" do
    lambda {
      class BadNestedTypeInBlockRecord < BinData::Record
        array :a do
          non_registered_type
        end
      end
    }.must_raise_on_line TypeError, 3, "unknown type 'non_registered_type' in BinData::Array"
  end

  it "fails on nested choice when missing names" do
    lambda {
      class MissingChoiceNamesRecord < BinData::Record
        choice do
          int8 :a
          int8
        end
      end
    }.must_raise_on_line SyntaxError, 4, "fields must either all have names, or none must have names in BinData::Choice"
  end

  it "fails on malformed names" do
    lambda {
      class MalformedNameRecord < BinData::Record
        int8 :a
        int8 "45"
      end
    }.must_raise_on_line NameError, 3, "field '45' is an illegal fieldname in MalformedNameRecord"
  end

  it "fails on duplicate names" do
    lambda {
      class DuplicateNameRecord < BinData::Record
        int8 :a
        int8 :b
        int8 :a
      end
    }.must_raise_on_line SyntaxError, 4, "duplicate field 'a' in DuplicateNameRecord"
  end

  it "fails on reserved names" do
    lambda {
      class ReservedNameRecord < BinData::Record
        int8 :a
        int8 :invert # from Hash.instance_methods
      end
    }.must_raise_on_line NameError, 3, "field 'invert' is a reserved name in ReservedNameRecord"
  end

  it "fails when field name shadows an existing method" do
    lambda {
      class ExistingNameRecord < BinData::Record
        int8 :object_id
      end
    }.must_raise_on_line NameError, 2, "field 'object_id' shadows an existing method in ExistingNameRecord"
  end

  it "fails on unknown endian" do
    lambda {
      class BadEndianRecord < BinData::Record
        endian 'a bad value'
      end
    }.must_raise_on_line ArgumentError, 2, "unknown value for endian 'a bad value' in BadEndianRecord"
  end

  it "fails when endian is after a field" do
    lambda {
      class BadEndianPosRecord < BinData::Record
        string :a
        endian :little
      end
    }.must_raise_on_line SyntaxError, 3, "endian must be called before defining fields in BadEndianPosRecord"
  end

  it "fails when search_prefix is after a field" do
    lambda {
      class BadSearchPrefixPosRecord < BinData::Record
        string :a
        search_prefix :pre
      end
    }.must_raise_on_line SyntaxError, 3, "search_prefix must be called before defining fields in BadSearchPrefixPosRecord"
  end
end

describe BinData::Record, "with anonymous fields" do
  class AnonymousRecord < BinData::Record
    int8 'a', initial_value: 10
    int8 ''
    int8 nil
    int8
    int8 value: :a
  end

  let(:obj) { AnonymousRecord.new }

  it "only shows non anonymous fields" do
    obj.field_names.must_equal [:a]
  end

  it "does not include anonymous fields in snapshot" do
    obj.a = 5
    obj.snapshot.must_equal({a: 5})
  end

  it "writes anonymous fields" do
    str = "\001\002\003\004\005"
    obj.read(str)
    obj.a.clear
    obj.to_binary_s.must_equal_binary "\012\002\003\004\012"
  end
end

describe BinData::Record, "with hidden fields" do
  class HiddenRecord < BinData::Record
    hide :b, :c
    int8 :a
    int8 'b', initial_value: 10
    int8 :c
    int8 :d, value: :b
  end

  let(:obj) { HiddenRecord.new }

  it "only shows fields that aren't hidden" do
    obj.field_names.must_equal [:a, :d]
  end

  it "accesses hidden fields directly" do
    obj.b.must_equal 10
    obj.c = 15
    obj.c.must_equal 15

    obj.must_respond_to :b=
  end

  it "does not include hidden fields in snapshot" do
    obj.b = 5
    obj.snapshot.must_equal({a: 0, d: 5})
  end
end

describe BinData::Record, "with multiple fields" do
  class MultiFieldRecord < BinData::Record
    int8 :a
    int8 :b
  end

  let(:obj) { MultiFieldRecord.new(a: 1, b: 2) }

  it "returns num_bytes" do
    obj.a.num_bytes.must_equal 1
    obj.b.num_bytes.must_equal 1
    obj.num_bytes.must_equal   2
  end

  it "identifies accepted parameters" do
    BinData::Record.accepted_parameters.all.must_include :hide
    BinData::Record.accepted_parameters.all.must_include :endian
  end

  it "clears" do
    obj.a = 6
    obj.clear
    assert obj.clear?
  end

  it "clears individual elements" do
    obj.a = 6
    obj.b = 7
    obj.a.clear
    assert obj.a.clear?
    refute obj.b.clear?
  end

  it "writes ordered" do
    obj.to_binary_s.must_equal_binary "\x01\x02"
  end

  it "reads ordered" do
    obj.read("\x03\x04")

    obj.a.must_equal 3
    obj.b.must_equal 4
  end

  it "returns a snapshot" do
    snap = obj.snapshot
    snap.a.must_equal 1
    snap.b.must_equal 2
    snap.must_equal({ a: 1, b: 2 })
  end

  it "returns field_names" do
    obj.field_names.must_equal [:a, :b]
  end
  
  it "fails on unknown method call" do
    lambda { obj.does_not_exist }.must_raise NoMethodError
  end
end

describe BinData::Record, "with nested structs" do
  class NestedStructRecord < BinData::Record
    int8   :a, initial_value: 6
    struct :b, the_val: :a do
      hide :w
      int8 :w, initial_value: 3
      int8 :x, value: :the_val
    end
    struct :c do
      int8 :y, value: -> { b.w }
      int8 :z
    end
  end

  let(:obj) { NestedStructRecord.new }

  it "includes nested field names" do
    obj.field_names.must_equal [:a, :b, :c]
  end

  it "hides nested field names" do
    obj.b.field_names.must_equal [:x]
  end

  it "accesses nested fields" do
    obj.a.must_equal   6
    obj.b.w.must_equal 3
    obj.b.x.must_equal 6
    obj.c.y.must_equal 3
  end

  it "returns correct abs_offset" do
    obj.abs_offset.must_equal 0
    obj.b.abs_offset.must_equal 1
    obj.b.w.abs_offset.must_equal 1
    obj.c.abs_offset.must_equal 3
    obj.c.z.abs_offset.must_equal 4
  end

  it "returns correct rel_offset" do
    obj.rel_offset.must_equal 0
    obj.b.rel_offset.must_equal 1
    obj.b.w.rel_offset.must_equal 0
    obj.c.rel_offset.must_equal 3
    obj.c.z.rel_offset.must_equal 1
  end

  it "assigns nested fields" do
    obj.assign(a: 2, b: {w: 4})
    obj.a.must_equal   2
    obj.b.w.must_equal 4
    obj.b.x.must_equal 2
    obj.c.y.must_equal 4
  end
end

describe BinData::Record, "with nested array of primitives" do
  class NestedPrimitiveArrayRecord < BinData::Record
    array :a, initial_length: 3 do
      uint8 value: -> { index }
    end
  end

  let(:obj) { NestedPrimitiveArrayRecord.new }

  it "uses block as :type" do
    obj.snapshot.must_equal({a: [0, 1, 2]})
  end
end

describe BinData::Record, "with nested array of structs" do
  class NestedStructArrayRecord < BinData::Record
    array :a do
      uint8 :b
      uint8 :c
    end
  end

  let(:obj) { NestedStructArrayRecord.new }

  it "uses block as struct for :type" do
    obj.a[0].b = 2
    obj.snapshot.must_equal({a: [{b: 2, c: 0}]})
  end
end

describe BinData::Record, "with nested choice with implied keys" do
  class NestedChoiceWithImpliedKeysRecord < BinData::Record
    choice :a, selection: 1 do
      uint8 value: 1
      uint8 value: 2
    end
  end

  let(:obj) { NestedChoiceWithImpliedKeysRecord.new }

  specify { obj.a.must_equal 2 }
end

describe BinData::Record, "with nested choice with explicit keys" do
  class NestedChoiceWithKeysRecord < BinData::Record
    choice :a, selection: 5 do
      uint8 3, value: 1
      uint8 5, value: 2
    end
  end

  let(:obj) { NestedChoiceWithKeysRecord.new }

  specify { obj.a.must_equal 2 }
end

describe BinData::Record, "with nested choice with names" do
  class NestedChoiceWithNamesRecord < BinData::Record
    choice :a, selection: "b" do
      uint8 "b", value: 1
      uint8 "c", value: 2
    end
  end

  let(:obj) { NestedChoiceWithNamesRecord.new }

  specify { obj.a.must_equal 1 }
end

describe BinData::Record, "with an endian defined" do
  class RecordWithEndian < BinData::Record
    endian :little

    uint16 :a
    float  :b
    array  :c, initial_length: 2 do
      int8
    end
    choice :d, selection: 1 do
      uint16
      uint32
    end
    struct :e do
      uint16   :f
      uint32be :g
    end
    struct :h do
      endian :big
      struct :i do
        uint16 :j
      end
    end
  end

  let(:obj) { RecordWithEndian.new }

  it "uses correct endian" do
    obj.a = 1
    obj.b = 2.0
    obj.c[0] = 3
    obj.c[1] = 4
    obj.d = 5
    obj.e.f = 6
    obj.e.g = 7
    obj.h.i.j = 8

    lambdaed = [1, 2.0, 3, 4, 5, 6, 7, 8].pack('veCCVvNn')

    obj.to_binary_s.must_equal_binary lambdaed
  end
end

describe BinData::Record, "with search_prefix" do
  class ASprefix < BinData::Int8; end
  class BSprefix < BinData::Int8; end

  class RecordWithSearchPrefix < BinData::Record
    search_prefix :a
    sprefix :f
  end

  class RecordWithParentSearchPrefix < BinData::Record
    search_prefix :a
    struct :s do
      sprefix :f
    end
  end

  class RecordWithNestedSearchPrefix < BinData::Record
    search_prefix :a
    struct :s do
      search_prefix :x
      sprefix :f
    end
  end

  class RecordWithPrioritisedNestedSearchPrefix < BinData::Record
    search_prefix :b
    struct :s do
      search_prefix :a
      sprefix :f
    end
  end

  it "uses search_prefix" do
    obj = RecordWithSearchPrefix.new
    obj.f.class.name.must_equal "ASprefix"
  end

  it "uses parent search_prefix" do
    obj = RecordWithParentSearchPrefix.new
    obj.s.f.class.name.must_equal "ASprefix"
  end

  it "uses nested search_prefix" do
    obj = RecordWithNestedSearchPrefix.new
    obj.s.f.class.name.must_equal "ASprefix"
  end

  it "uses prioritised nested search_prefix" do
    obj = RecordWithPrioritisedNestedSearchPrefix.new
    obj.s.f.class.name.must_equal "ASprefix"
  end
end

describe BinData::Record, "with endian :big_and_little" do
  class RecordWithBnLEndian < BinData::Record
    endian :big_and_little
    int16 :a, value: 1
  end

  it "is not registered" do
    lambda {
      BinData::RegisteredClasses.lookup("RecordWithBnLEndian")
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "creates big endian version" do
    obj = RecordWithBnLEndianBe.new
    obj.to_binary_s.must_equal_binary "\x00\x01"
  end

  it "creates little endian version" do
    obj = RecordWithBnLEndianLe.new
    obj.to_binary_s.must_equal_binary "\x01\x00"
  end

  it "requires :endian as argument" do
    lambda {
      RecordWithBnLEndian.new
    }.must_raise ArgumentError
  end

  it "accepts :endian as argument" do
    obj = RecordWithBnLEndian.new(endian: :little)
    obj.to_binary_s.must_equal_binary "\x01\x00"
  end
end

describe BinData::Record, "with endian :big_and_little and search_prefix" do
  class NsBNLIntBe < BinData::Int16be; end
  class NsBNLIntLe < BinData::Int16le; end

  class RecordWithBnLEndianAndSearchPrefix < BinData::Record
    endian :big_and_little
    search_prefix :ns
     bnl_int :a, value: 1
  end

  it "creates big endian version" do
    obj = RecordWithBnLEndianAndSearchPrefixBe.new
    obj.to_binary_s.must_equal_binary "\x00\x01"
  end

  it "creates little endian version" do
    obj = RecordWithBnLEndianAndSearchPrefixLe.new
    obj.to_binary_s.must_equal_binary "\x01\x00"
  end
end

describe BinData::Record, "with endian :big_and_little when subclassed" do
  class ARecordWithBnLEndian < BinData::Record
    endian :big_and_little
    int16 :a, value: 1
  end
  class BRecordWithBnLEndian < ARecordWithBnLEndian
    int16 :b, value: 2
  end

  it "is not registered" do
    lambda {
      BinData::RegisteredClasses.lookup("BRecordWithBnLEndian")
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "creates big endian version" do
    obj = BRecordWithBnLEndianBe.new
    obj.to_binary_s.must_equal_binary "\x00\x01\x00\x02"
  end

  it "creates little endian version" do
    obj = BRecordWithBnLEndianLe.new
    obj.to_binary_s.must_equal_binary "\x01\x00\x02\x00"
  end

  it "requires :endian as argument" do
    lambda {
      BRecordWithBnLEndian.new
    }.must_raise ArgumentError
  end

  it "accepts :endian as argument" do
    obj = BRecordWithBnLEndian.new(endian: :little)
    obj.to_binary_s.must_equal_binary "\x01\x00\x02\x00"
  end
end

describe BinData::Record, "defined recursively" do
  class RecursiveRecord < BinData::Record
    endian  :big
    uint16  :val
    uint8   :has_nxt, value: -> { nxt.clear? ? 0 : 1 }
    recursive_record :nxt, onlyif: -> { has_nxt > 0 }
  end

  it "can be created" do
    RecursiveRecord.new
  end

  it "reads" do
    str = "\x00\x01\x01\x00\x02\x01\x00\x03\x00"
    obj = RecursiveRecord.read(str)
    obj.val.must_equal 1
    obj.nxt.val.must_equal 2
    obj.nxt.nxt.val.must_equal 3
  end

  it "is assignable on demand" do
    obj = RecursiveRecord.new
    obj.val = 13
    obj.nxt.val = 14
    obj.nxt.nxt.val = 15
  end

  it "writes" do
    obj = RecursiveRecord.new
    obj.val = 5
    obj.nxt.val = 6
    obj.nxt.nxt.val = 7
    obj.to_binary_s.must_equal_binary "\x00\x05\x01\x00\x06\x01\x00\x07\x00"
  end
end

describe BinData::Record, "with custom mandatory parameters" do
  class MandatoryRecord < BinData::Record
    mandatory_parameter :arg1

    uint8 :a, value: :arg1
  end

  it "raises error if mandatory parameter is not supplied" do
    lambda { MandatoryRecord.new }.must_raise ArgumentError
  end

  it "uses mandatory parameter" do
    obj = MandatoryRecord.new(arg1: 5)
    obj.a.must_equal 5
  end
end

describe BinData::Record, "with custom default parameters" do
  class DefaultRecord < BinData::Record
    default_parameter arg1: 5

    uint8 :a, value: :arg1
    uint8 :b
  end

  it "uses default parameter" do
    obj = DefaultRecord.new
    obj.a.must_equal 5
  end

  it "overrides default parameter" do
    obj = DefaultRecord.new(arg1: 7)
    obj.a.must_equal 7
  end

  it "accepts values" do
    obj = DefaultRecord.new(b: 2)
    obj.b.must_equal 2
  end

  it "accepts values and parameters" do
    obj = DefaultRecord.new({b: 2}, arg1: 3)
    obj.a.must_equal 3
    obj.b.must_equal 2
  end
end

describe BinData::Record, "with :onlyif" do
  class OnlyIfRecord < BinData::Record
    uint8 :a, initial_value: 3
    uint8 :b, initial_value: 5, onlyif: -> { a == 3 }
    uint8 :c, initial_value: 7, onlyif: -> { a != 3 }
  end

  let(:obj) { OnlyIfRecord.new }

  it "initial state" do
    obj.num_bytes.must_equal 2
    obj.snapshot.must_equal({a: 3, b: 5})
    obj.to_binary_s.must_equal_binary "\x03\x05"
  end

  it "identifies if fields are included" do
    obj.a?.must_equal true
    obj.b?.must_equal true
    obj.c?.must_equal false
  end

  it "reads as lambdaed" do
    obj.read("\x01\x02")
    obj.snapshot.must_equal({a: 1, c: 2})
  end
end

describe BinData::Record, "derived classes" do
  class ParentRecord < BinData::Record
    uint8 :a
  end

  class Child1Record < ParentRecord
    uint8 :b
  end

  class Child2Record < Child1Record
    uint8 :c
  end

  it "does not affect parent" do
    ParentRecord.new.field_names.must_equal [:a]
  end

  it "inherits fields for first child" do
    Child1Record.new.field_names.must_equal [:a, :b]
  end

  it "inherits fields for second child" do
    Child2Record.new.field_names.must_equal [:a, :b, :c]
  end
end
