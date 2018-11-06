# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Server::DocServerSerializer do
  describe "#serialized_path" do
    before do
      Registry.clear
      @serializer = Server::DocServerSerializer.new
    end

    after(:all) { Server::Adapter.shutdown }

    it "returns '/PREFIX/library/toplevel' for root" do
      expect(@serializer.serialized_path(Registry.root)).to eq "toplevel"
    end

    it "returns /PREFIX/library/Object for Object in a library" do
      expect(@serializer.serialized_path(P('A::B::C'))).to eq 'A/B/C'
    end

    it "links to instance method as Class:method" do
      obj = CodeObjects::MethodObject.new(:root, :method)
      expect(@serializer.serialized_path(obj)).to eq 'toplevel:method'
    end

    it "links to class method as Class.method" do
      obj = CodeObjects::MethodObject.new(:root, :method, :class)
      expect(@serializer.serialized_path(obj)).to eq 'toplevel.method'
    end

    it "links to anchor for constant" do
      obj = CodeObjects::ConstantObject.new(:root, :FOO)
      expect(@serializer.serialized_path(obj)).to eq 'toplevel#FOO-constant'
    end

    it "links to anchor for class variable" do
      obj = CodeObjects::ClassVariableObject.new(:root, :@@foo)
      expect(@serializer.serialized_path(obj)).to eq 'toplevel#@@foo-classvariable'
    end

    it "links files using file/ prefix" do
      file = CodeObjects::ExtraFileObject.new('a/b/FooBar.md', '')
      expect(@serializer.serialized_path(file)).to eq 'file/FooBar'
    end

    it "escapes special characters" do
      obj = CodeObjects::MethodObject.new(:root, :method?)
      expect(@serializer.serialized_path(obj)).to eq 'toplevel:method%3F'
    end

    it "handles unicode data" do
      file = CodeObjects::ExtraFileObject.new("test\u0160", '')
      if file.name.encoding == Encoding.find("Windows-1252")
        expect(@serializer.serialized_path(file)).to eq 'file/test_8A'
      else
        expect(@serializer.serialized_path(file)).to eq 'file/test_C5A0'
      end
    end if defined?(::Encoding)
  end
end
