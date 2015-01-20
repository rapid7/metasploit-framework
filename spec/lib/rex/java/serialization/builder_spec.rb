# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'

describe Rex::Java::Serialization::Builder do
  subject(:builder) do
    described_class.new
  end

  let(:class_opts) do
    {
      name: 'java.rmi.MarshalledObject',
      serial: 0x7cbd1e97ed63fc3e,
      fields: [
        ['int', 'hash'],
        ['array', 'locBytes', '[B'],
        ['array', 'objBytes', '[B']
      ]
    }
  end

  let(:object_opts) do
    {
      data: [["int", 1]]
    }
  end

  let(:array_opts) do
    {
      values_type: 'byte',
      values: [0x41, 0x42, 0x43, 0x44]
    }
  end

  describe ".new" do
    it "returns a Rex::Java::Serialization::Builder" do
      expect(builder).to be_a(Rex::Java::Serialization::Builder)
    end
  end

  describe "#new_class" do
    context "when no options" do
      it "returns a Rex::Java::Serialization::Model::NewClassDesc" do
        expect(builder.new_class).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
      end

      it "sets an empty class name" do
        expect(builder.new_class.class_name.contents).to eq('')
      end

      it "sets a 0 serial version" do
        expect(builder.new_class.serial_version).to eq(0)
      end

      it "sets flags to SC_SERIALIZABLE" do
        expect(builder.new_class.flags).to eq(Rex::Java::Serialization::SC_SERIALIZABLE)
      end

      it "sets default annotations" do
        expect(builder.new_class.class_annotation.contents.length).to eq(2)
      end

      it "sets empty fields" do
        expect(builder.new_class.fields.length).to eq(0)
      end

      it "sets null super class" do
        expect(builder.new_class.super_class.description).to be_a(Rex::Java::Serialization::Model::NullReference)
      end
    end

    context "when options" do
      it "returns a Rex::Java::Serialization::Model::NewClassDesc" do
        expect(builder.new_class(class_opts)).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
      end

      it "sets the class name from options" do
        expect(builder.new_class(class_opts).class_name.contents).to eq(class_opts[:name])
      end

      it "sets serial version from options" do
        expect(builder.new_class(class_opts).serial_version).to eq(class_opts[:serial])
      end

      it "sets fields from options" do
        expect(builder.new_class(class_opts).fields.length).to eq(3)
      end
    end
  end

  describe "#new_object" do
    context "when no options" do
      it "returns a Rex::Java::Serialization::Model::NewObject" do
        expect(builder.new_object).to be_a(Rex::Java::Serialization::Model::NewObject)
      end

      it "sets empty data" do
        expect(builder.new_object.class_data).to eq([])
      end
    end

    context "when options" do
      it "returns a Rex::Java::Serialization::Model::NewObject" do
        expect(builder.new_object(object_opts)).to be_a(Rex::Java::Serialization::Model::NewObject)
      end

      it "sets data from options" do
        expect(builder.new_object(object_opts).class_data[0][1]).to eq(1)
      end
    end
  end

  describe "#new_array" do
    context "when no options" do
      it "returns a Rex::Java::Serialization::Model::NewArray" do
        expect(builder.new_array).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "sets empty values type" do
        expect(builder.new_array.type).to eq('')
      end

      it "sets empty values array" do
        expect(builder.new_array.values).to eq([])
      end
    end

    context "when options" do
      it "returns a Rex::Java::Serialization::Model::NewArray" do
        expect(builder.new_array(array_opts)).to be_a(Rex::Java::Serialization::Model::NewArray)
      end

      it "sets empty values type" do
        expect(builder.new_array(array_opts).type).to eq(array_opts[:values_type])
      end

      it "sets empty values array" do
        expect(builder.new_array(array_opts).values).to eq(array_opts[:values])
      end
    end
  end
end