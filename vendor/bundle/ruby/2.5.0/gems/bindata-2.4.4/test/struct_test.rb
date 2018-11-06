#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Struct, "when initializing" do
  it "fails on non registered types" do
    params = {fields: [[:non_registered_type, :a]]}
    lambda {
      BinData::Struct.new(params)
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "fails on duplicate names" do
    params = {fields: [[:int8, :a], [:int8, :b], [:int8, :a]]}
    lambda {
      BinData::Struct.new(params)
    }.must_raise NameError
  end

  it "fails on reserved names" do
    # note that #invert is from Hash.instance_methods
    params = {fields: [[:int8, :a], [:int8, :invert]]}
    lambda {
      BinData::Struct.new(params)
    }.must_raise NameError
  end

  it "fails when field name shadows an existing method" do
    params = {fields: [[:int8, :object_id]]}
    lambda {
      BinData::Struct.new(params)
    }.must_raise NameError
  end

  it "fails on unknown endian" do
    params = {endian: 'bad value', fields: []}
    lambda {
      BinData::Struct.new(params)
    }.must_raise ArgumentError
  end
end

describe BinData::Struct, "with anonymous fields" do
  let(:obj) {
    params = { fields: [
                            [:int8, :a, {initial_value: 5}],
                            [:int8, nil],
                            [:int8, '', {value: :a}]
                          ] }
    BinData::Struct.new(params)
  }

  it "only shows non anonymous fields" do
    obj.field_names.must_equal [:a]
  end

  it "does not include anonymous fields in snapshot" do
    obj.a = 5
    obj.snapshot.must_equal({a: 5})
  end

  it "writes anonymous fields" do
    obj.read("\001\002\003")
    obj.a.clear
    obj.to_binary_s.must_equal_binary "\005\002\005"
  end
end

describe BinData::Struct, "with hidden fields" do
  let(:obj) {
    params = { hide: [:b, :c],
               fields: [
                   [:int8, :a],
                   [:int8, 'b', {initial_value: 5}],
                   [:int8, :c],
                   [:int8, :d, {value: :b}]] }
    BinData::Struct.new(params)
  }

  it "only shows fields that aren't hidden" do
    obj.field_names.must_equal [:a, :d]
  end

  it "shows all fields when requested" do
    obj.field_names(true).must_equal [:a, :b, :c, :d]
  end

  it "accesses hidden fields directly" do
    obj.b.must_equal 5
    obj.c = 15
    obj.c.must_equal 15

    obj.must_respond_to :b=
  end

  it "does not include hidden fields in snapshot" do
    obj.b = 7
    obj.snapshot.must_equal({a: 0, d: 7})
  end

  it "detects hidden fields with has_key?" do
    assert obj.has_key?("b")
  end
end

describe BinData::Struct, "with multiple fields" do
  let(:params) { { fields: [ [:int8, :a], [:int8, :b] ] } }
  let(:obj) { BinData::Struct.new({a: 1, b: 2}, params) }

  specify { obj.field_names.must_equal [:a, :b] }
  specify { obj.to_binary_s.must_equal_binary "\x01\x02" }

  it "returns num_bytes" do
    obj.a.num_bytes.must_equal 1
    obj.b.num_bytes.must_equal 1
    obj.num_bytes.must_equal   2
  end

  it "identifies accepted parameters" do
    BinData::Struct.accepted_parameters.all.must_include :fields
    BinData::Struct.accepted_parameters.all.must_include :hide
    BinData::Struct.accepted_parameters.all.must_include :endian
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

  it "reads elements dynamically" do
    obj[:a].must_equal 1
  end

  it "handles not existing elements" do
    obj[:does_not_exist].must_be_nil
  end

  it "writes elements dynamically" do
    obj[:a] = 2
    obj.a.must_equal 2
  end

  it "implements has_key?" do
    assert obj.has_key?("a")
  end

  it "reads ordered" do
    obj.read("\x03\x04")

    obj.a.must_equal 3
    obj.b.must_equal 4
  end

  it "returns a snapshot" do
    snap = obj.snapshot
    assert snap.respond_to?(:a)
    snap.a.must_equal 1
    snap.b.must_equal 2
    snap.must_equal({ a: 1, b: 2 })
  end

  it "assigns from partial hash" do
    obj.assign(a: 3)
    obj.a.must_equal 3
    obj.b.must_equal 0
  end

  it "assigns from hash" do
    obj.assign(a: 3, b: 4)
    obj.a.must_equal 3
    obj.b.must_equal 4
  end

  it "assigns from nil" do
    obj.assign(nil)
    assert obj.clear?
  end

  it "assigns from Struct" do
    src = BinData::Struct.new(params)
    src.a = 3
    src.b = 4

    obj.assign(src)
    obj.a.must_equal 3
    obj.b.must_equal 4
  end

  it "assigns from snapshot" do
    src = BinData::Struct.new(params)
    src.a = 3
    src.b = 4

    obj.assign(src.snapshot)
    obj.a.must_equal 3
    obj.b.must_equal 4
  end

  it "fails on unknown method call" do
    lambda { obj.does_not_exist }.must_raise NoMethodError
  end

  describe "#snapshot" do
    it "has ordered #keys" do
      obj.snapshot.keys.must_equal [:a, :b]
    end

    it "has ordered #each" do
      keys = []
      obj.snapshot.each { |el| keys << el[0] }
      keys.must_equal [:a, :b]
    end

    it "has ordered #each_pair" do
      keys = []
      obj.snapshot.each_pair { |k, v| keys << k }
      keys.must_equal [:a, :b]
    end
  end
end

describe BinData::Struct, "with nested structs" do
  let(:obj) {
    inner1 = [ [:int8, :w, {initial_value: 3}],
               [:int8, :x, {value: :the_val}] ]

    inner2 = [ [:int8, :y, {value: -> { parent.b.w }}],
               [:int8, :z] ]

    params = { fields: [
                 [:int8, :a, {initial_value: 6}],
                 [:struct, :b, {fields: inner1, the_val: :a}],
                 [:struct, :c, {fields: inner2}]] }
    BinData::Struct.new(params)
  }

  specify { obj.field_names.must_equal [:a, :b, :c] }

  it "returns num_bytes" do
    obj.b.num_bytes.must_equal 2
    obj.c.num_bytes.must_equal 2
    obj.num_bytes.must_equal 5
  end

  it "accesses nested fields" do
    obj.a.must_equal   6
    obj.b.w.must_equal 3
    obj.b.x.must_equal 6
    obj.c.y.must_equal 3
    obj.c.z.must_equal 0
  end

  it "returns correct abs_offset" do
    obj.b.abs_offset.must_equal 1
    obj.b.w.abs_offset.must_equal 1
    obj.c.abs_offset.must_equal 3
    obj.c.z.abs_offset.must_equal 4
  end
end

describe BinData::Struct, "with an endian defined" do
  let(:obj) {
    BinData::Struct.new(endian: :little,
                        fields: [
                                  [:uint16, :a],
                                  [:float, :b],
                                  [:array, :c,
                                    {type: :int8, initial_length: 2}],
                                  [:choice, :d,
                                    {choices: [[:uint16], [:uint32]],
                                     selection: 1}],
                                  [:struct, :e,
                                    {fields: [[:uint16, :f],
                                                 [:uint32be, :g]]}],
                                  [:struct, :h,
                                    {fields: [
                                      [:struct, :i,
                                        {fields: [[:uint16, :j]]}]]}]
                                ])
  }

  it "uses correct endian" do
    obj.a = 1
    obj.b = 2.0
    obj.c[0] = 3
    obj.c[1] = 4
    obj.d = 5
    obj.e.f = 6
    obj.e.g = 7
    obj.h.i.j = 8

    expected = [1, 2.0, 3, 4, 5, 6, 7, 8].pack('veCCVvNv')

    obj.to_binary_s.must_equal_binary expected
  end
end

describe BinData::Struct, "with bit fields" do
  let(:obj) {
    params = { fields: [ [:bit1le, :a], [:bit2le, :b], [:uint8, :c], [:bit1le, :d] ] }
    BinData::Struct.new({a: 1, b: 2, c: 3, d: 1}, params)
  }

  specify { obj.num_bytes.must_equal 3 }
  specify { obj.to_binary_s.must_equal_binary [0b0000_0101, 3, 1].pack("C*") }

  it "reads" do
    str = [0b0000_0110, 5, 0].pack("C*")
    obj.read(str)
    obj.a.must_equal 0
    obj.b.must_equal 3
    obj.c.must_equal 5
    obj.d.must_equal 0
  end

  it "has correct offsets" do
    obj.a.rel_offset.must_equal 0
    obj.b.rel_offset.must_equal 0
    obj.c.rel_offset.must_equal 1
    obj.d.rel_offset.must_equal 2
  end
end

describe BinData::Struct, "with nested endian" do
  it "uses correct endian" do
    nested_params = { endian: :little,
                      fields: [[:int16, :b], [:int16, :c]] }
    params = { endian: :big, 
               fields: [[:int16, :a],
                        [:struct, :s, nested_params],
                        [:int16, :d]] }
    obj = BinData::Struct.new(params)
    obj.read("\x00\x01\x02\x00\x03\x00\x00\x04")

    obj.a.must_equal   1
    obj.s.b.must_equal 2
    obj.s.c.must_equal 3
    obj.d.must_equal   4
  end
end

describe BinData::Struct, "with a search_prefix" do
  class AShort < BinData::Uint8; end
  class BShort < BinData::Uint8; end

  it "searches symbol prefixes" do
    obj = BinData::Struct.new(search_prefix: :a,
                              fields: [ [:short, :f] ])
    obj.f.class.name.must_equal "AShort"
  end

  it "searches string prefixes" do
    obj = BinData::Struct.new(search_prefix: "a",
                              fields: [ [:short, :f] ])
    obj.f.class.name.must_equal "AShort"
  end

  it "searches string prefixes with optional underscore" do
    obj = BinData::Struct.new(search_prefix: "a_",
                              fields: [ [:short, :f] ])
    obj.f.class.name.must_equal "AShort"
  end

  it "searches multiple prefixes" do
    obj = BinData::Struct.new(search_prefix: [:x, :a],
                              fields: [ [:short, :f] ])
    obj.f.class.name.must_equal "AShort"
  end

  it "uses parent search_prefix" do
    nested_params = { fields: [[:short, :f]] }
    obj = BinData::Struct.new(search_prefix: :a,
                              fields: [[:struct, :s, nested_params]])
    obj.s.f.class.name.must_equal "AShort"
  end

  it "searches parent search_prefix" do
    nested_params = { search_prefix: :x, fields: [[:short, :f]] }
    obj = BinData::Struct.new(search_prefix: :a,
                              fields: [[:struct, :s, nested_params]])
    obj.s.f.class.name.must_equal "AShort"
  end

  it "prioritises nested search_prefix" do
    nested_params = { search_prefix: :a, fields: [[:short, :f]] }
    obj = BinData::Struct.new(search_prefix: :b,
                              fields: [[:struct, :s, nested_params]])
    obj.s.f.class.name.must_equal "AShort"
  end
end

describe BinData::Struct, "with byte_align" do
  let(:obj) {
    params = { fields: [[:int8, :a],
                        [:int8, :b, byte_align: 5],
                        [:bit2, :c],
                        [:int8, :d, byte_align: 3]] }
    BinData::Struct.new(params)
  }

  it "has #num_bytes" do
    obj.num_bytes.must_equal 10
  end

  it "reads" do
    obj.read("\x01\x00\x00\x00\x00\x02\xc0\x00\x00\x04")
    obj.snapshot.must_equal({ a: 1, b: 2, c: 3, d: 4 })
  end

  it "writes" do
    obj.assign(a: 1, b: 2, c: 3, d: 4)
    obj.to_binary_s.must_equal_binary "\x01\x00\x00\x00\x00\x02\xc0\x00\x00\x04"
  end

  it "has correct offsets" do
    obj.a.rel_offset.must_equal 0
    obj.b.rel_offset.must_equal 5
    obj.c.rel_offset.must_equal 6
    obj.d.rel_offset.must_equal 9
  end
end

describe BinData::Struct, "with dynamically named types" do
  it "instantiates" do
    _ = BinData::Struct.new(name: :my_struct, fields: [[:int8, :a, {initial_value: 3}]])

    obj = BinData::Struct.new(fields: [[:my_struct, :v]])

    obj.v.a.must_equal 3
  end
end
