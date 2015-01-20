# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'

describe Rex::Java::Serialization::Builder do
  subject(:builder) do
    described_class.new
  end

  let(:opts) do
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
        expect(builder.new_class(opts)).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
      end

      it "sets the class name from options" do
        expect(builder.new_class(opts).class_name.contents).to eq(opts[:name])
      end

      it "sets serial version from options" do
        expect(builder.new_class(opts).serial_version).to eq(opts[:serial])
      end

      it "sets fields from options" do
        expect(builder.new_class(opts).fields.length).to eq(3)
      end
    end
  end
end