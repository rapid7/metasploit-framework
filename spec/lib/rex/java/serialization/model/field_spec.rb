# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::Field do
  subject(:field) do
    described_class.new
  end

  let(:sample_primitive) { "I\x00\x06number" }
  let(:sample_primitive_io) { StringIO.new(sample_primitive) }
  let(:sample_object) { "[\x00\x0atest_arrayt\x00\x0b[LEmployee;" }
  let(:sample_object_io) { StringIO.new(sample_object) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::Field" do
      expect(field).to be_a(Rex::Java::Serialization::Model::Field)
    end

    it "initializes code with empty string" do
      expect(field.type).to be_empty
    end

    it "initializes name with nil" do
      expect(field.name).to be_nil
    end

    it "initializes field_type with nil" do
      expect(field.field_type).to be_nil
    end
  end

  describe "#encode" do
    context "when empty field" do
      it { expect { field.encode }.to raise_error(::RuntimeError) }
    end

    context "when primitive field" do
      it do
        field.type = 'int'
        field.name = Rex::Java::Serialization::Model::Utf.new(nil, 'number')
        expect(field.encode).to eq(sample_primitive)
      end
    end

    context "when object field" do
      it do
        field.type = 'array'
        field.name = Rex::Java::Serialization::Model::Utf.new(nil, 'test_array')
        field.field_type = Rex::Java::Serialization::Model::Utf.new(nil, '[LEmployee;')
        expect(field.encode).to eq(sample_object)
      end
    end
  end

  describe "#decode" do
    context "when stream contains a primitive field" do
      it "returns a Rex::Java::Serialization::Model::Field" do
        expect(field.decode(sample_primitive_io)).to be_a(Rex::Java::Serialization::Model::Field)
      end

      it "deserializes field type" do
        field.decode(sample_primitive_io)
        expect(field.type).to eq('int')
      end

      it "deserializes field name as Utf" do
        field.decode(sample_primitive_io)
        expect(field.name.contents).to eq('number')
      end
    end

    context "when stream contains an object field" do
      it "returns a Rex::Java::Serialization::Model::Field" do
        expect(field.decode(sample_object_io)).to be_a(Rex::Java::Serialization::Model::Field)
      end

      it "deserializes field type" do
        field.decode(sample_object_io)
        expect(field.type).to eq('array')
      end

      it "deserializes field name" do
        field.decode(sample_object_io)
        expect(field.name.contents).to eq('test_array')
      end

      it "deserializes field_type string" do
        field.decode(sample_object_io)
        expect(field.field_type.contents).to eq('[LEmployee;')
      end
    end
  end

  describe "#to_s" do
    it "prints an stream containing a primitive field" do
      field.decode(sample_primitive_io)
      expect(field.to_s).to eq('number (int)')
    end

    it "prints an stream containing an object field" do
      field.decode(sample_object_io)
      expect(field.to_s).to eq('test_array ([LEmployee;)')
    end
  end
end