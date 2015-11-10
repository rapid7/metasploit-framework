# -*- coding:binary -*-
require 'spec_helper'

require 'rex/java'
require 'stringio'

describe Rex::Java::Serialization::Model::ProxyClassDesc do
  subject(:proxy_class_desc) do
    described_class.new
  end

  let(:sample) do
    "\x00\x00\x00\x01\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x68\x65" +
    "\x6c\x6c\x6f\x2e\x48\x65\x6c\x6c\x6f\x70\x78\x72\x00\x17\x6a\x61" +
    "\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x72\x65\x66\x6c\x65\x63\x74\x2e" +
    "\x50\x72\x6f\x78\x79\xe1\x27\xda\x20\xcc\x10\x43\xcb\x02\x00\x01" +
    "\x4c\x00\x01\x68\x74\x00\x25\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e" +
    "\x67\x2f\x72\x65\x66\x6c\x65\x63\x74\x2f\x49\x6e\x76\x6f\x63\x61" +
    "\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x3b\x70\x78\x70"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe ".new" do
    it "Rex::Java::Serialization::Model::ProxyClassDesc" do
      expect(proxy_class_desc).to be_a(Rex::Java::Serialization::Model::ProxyClassDesc)
    end

    it "initializes interfaces with empty Array" do
      expect(proxy_class_desc.interfaces).to be_empty
    end

    it "initializes class_annotation with nil" do
      expect(proxy_class_desc.class_annotation).to be_nil
    end

    it "initializes super_class with nil" do
      expect(proxy_class_desc.super_class).to be_nil
    end
  end

  describe "#decode" do
    it "returns a Rex::Java::Serialization::Model::ProxyClassDesc" do
      expect(proxy_class_desc.decode(sample_io)).to be_a(Rex::Java::Serialization::Model::ProxyClassDesc)
    end

    it "deserializes interfaces" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.interfaces.length).to eq(1)
    end

    it "deserializes interfaces contents correctly" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.interfaces[0].contents).to eq('example.hello.Hello')
    end

    it "deserializes class annotation correctly" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.class_annotation).to be_a(Rex::Java::Serialization::Model::Annotation)
    end

    it "deserializes class annotation contents" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.class_annotation.contents[0]).to be_a(Rex::Java::Serialization::Model::NullReference)
    end

    it "deserializes super_class" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.super_class).to be_a(Rex::Java::Serialization::Model::ClassDesc)
    end

    it "deserializes super class description" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.super_class.description).to be_a(Rex::Java::Serialization::Model::NewClassDesc)
    end
  end

  describe "#encode" do
    it "serializes a ProxyClassDesc" do
      field = Rex::Java::Serialization::Model::Field.new
      field.type = 'object'
      field.name = Rex::Java::Serialization::Model::Utf.new(nil, 'h')
      field.field_type = Rex::Java::Serialization::Model::Utf.new(nil, 'Ljava/lang/reflect/InvocationHandler;')
      super_class_desc_new = Rex::Java::Serialization::Model::NewClassDesc.new
      super_class_desc_new.class_name = Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.reflect.Proxy')
      super_class_desc_new.serial_version = 0xe127da20cc1043cb
      super_class_desc_new.flags = 2
      super_class_desc_new.fields << field
      super_class_desc_new.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      super_class_desc_new.class_annotation.contents << Rex::Java::Serialization::Model::NullReference.new
      super_class_desc_new.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      super_class_desc_new.super_class = Rex::Java::Serialization::Model::ClassDesc.new
      super_class_desc_new.super_class.description = Rex::Java::Serialization::Model::NullReference.new

      super_class_desc = Rex::Java::Serialization::Model::ClassDesc.new
      super_class_desc.description = super_class_desc_new

      interface = Rex::Java::Serialization::Model::Utf.new(nil, 'example.hello.Hello')
      proxy_class_desc.interfaces << interface
      proxy_class_desc.class_annotation = Rex::Java::Serialization::Model::Annotation.new
      proxy_class_desc.class_annotation.contents << Rex::Java::Serialization::Model::NullReference.new
      proxy_class_desc.class_annotation.contents << Rex::Java::Serialization::Model::EndBlockData.new
      proxy_class_desc.super_class = super_class_desc

      expect(proxy_class_desc.encode).to eq(sample)
    end
  end

  describe "#to_s" do
    it "prints a sample NewClassDesc stream" do
      proxy_class_desc.decode(sample_io)
      expect(proxy_class_desc.to_s).to eq('[ example.hello.Hello ], @super_class: java.lang.reflect.Proxy')
    end
  end
end