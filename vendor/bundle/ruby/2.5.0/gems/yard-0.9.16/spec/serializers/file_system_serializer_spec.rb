# frozen_string_literal: true
require File.join(File.dirname(__FILE__), "spec_helper")

require 'stringio'

RSpec.describe YARD::Serializers::FileSystemSerializer do
  before do
    allow(FileUtils).to receive(:mkdir_p)
    allow(File).to receive(:open)
  end

  describe "#basepath" do
    it "defaults the base path to the 'doc/'" do
      obj = Serializers::FileSystemSerializer.new
      expect(obj.basepath).to eq 'doc'
    end
  end

  describe "#extension" do
    it "defaults the file extension to .html" do
      obj = Serializers::FileSystemSerializer.new
      expect(obj.extension).to eq "html"
    end
  end

  describe "#serialized_path" do
    it "allows no extension to be used" do
      obj = Serializers::FileSystemSerializer.new :extension => nil
      yard = CodeObjects::ClassObject.new(nil, :FooBar)
      expect(obj.serialized_path(yard)).to eq 'FooBar'
    end

    it "serializes to top-level-namespace for root" do
      obj = Serializers::FileSystemSerializer.new :extension => nil
      expect(obj.serialized_path(Registry.root)).to eq "top-level-namespace"
    end

    it "returns serialized_path for a String" do
      s = Serializers::FileSystemSerializer.new(:basepath => 'foo', :extension => 'txt')
      expect(s.serialized_path('test.txt')).to eq 'test.txt'
    end

    it "removes special chars from path" do
      m = CodeObjects::MethodObject.new(nil, 'a')
      s = Serializers::FileSystemSerializer.new

      {:gsub! => 'gsub_21_i.html',
        :ask? => 'ask_3F_i.html',
        :=== => '_3D_3D_3D_i.html',
        :+ => '_2B_i.html',
        :- => '-_i.html',
        :[]= => '_5B_5D_3D_i.html',
        :<< => '_3C_3C_i.html',
        :>= => '_3E_3D_i.html',
        :` => '_60_i.html',
        :& => '_26_i.html',
        :* => '_2A_i.html',
        :| => '_7C_i.html',
        :/ => '_2F_i.html',
        :=~ => '_3D_7E_i.html'}.each do |meth, value|
        allow(m).to receive(:name).and_return(meth)
        expect(s.serialized_path(m)).to eq value
      end
    end

    it "handles ExtraFileObject's" do
      s = Serializers::FileSystemSerializer.new
      e = CodeObjects::ExtraFileObject.new('filename.txt', '')
      expect(s.serialized_path(e)).to eq 'file.filename.html'
    end

    it "differentiates instance and class methods from serialized path" do
      s = Serializers::FileSystemSerializer.new
      m1 = CodeObjects::MethodObject.new(nil, 'meth')
      m2 = CodeObjects::MethodObject.new(nil, 'meth', :class)
      expect(s.serialized_path(m1)).not_to eq s.serialized_path(m2)
    end

    it "serializes path from overload tag" do
      YARD.parse_string <<-'eof'
        class Foo
          # @overload bar
          def bar; end
        end
      eof

      serializer = Serializers::FileSystemSerializer.new
      object = Registry.at('Foo#bar').tag(:overload)
      expect(serializer.serialized_path(object)).to eq "Foo/bar_i.html"
    end

    it "maps matching case sensitive object names to different files on disk" do
      Registry.clear
      o1 = CodeObjects::ClassObject.new(:root, "AB")
      o2 = CodeObjects::ClassObject.new(:root, "Ab")
      s = Serializers::FileSystemSerializer.new
      expect([["AB_.html", "Ab.html"], ["AB.html", "Ab_.html"]]).to include(
        [s.serialized_path(o1), s.serialized_path(o2)]
      )
    end

    it "handles case sensitivity of nested paths for objects with matching names" do
      Registry.clear
      YARD.parse_string <<-eof
        class Abc; class D; end end
        class ABC; class D; end end
      eof

      s = Serializers::FileSystemSerializer.new
      expect(s.serialized_path(Registry.at('ABC::D'))).to eq "ABC/D.html"
      expect(s.serialized_path(Registry.at('Abc::D'))).to eq "Abc/D.html"
    end
  end

  describe "#serialize" do
    it "serializes to the correct path" do
      yard = CodeObjects::ClassObject.new(nil, :FooBar)
      meth = CodeObjects::MethodObject.new(yard, :baz, :class)
      meth2 = CodeObjects::MethodObject.new(yard, :baz)

      {'foo/FooBar/baz_c.txt' => meth,
        'foo/FooBar/baz_i.txt' => meth2,
        'foo/FooBar.txt' => yard}.each do |path, obj|
        io = StringIO.new
        expect(File).to receive(:open).with(path, 'wb').and_yield(io)
        expect(io).to receive(:write).with("data")

        s = Serializers::FileSystemSerializer.new(:basepath => 'foo', :extension => 'txt')
        s.serialize(obj, "data")
      end
    end

    it "guarantees the directory exists" do
      o1 = CodeObjects::ClassObject.new(nil, :Really)
      o2 = CodeObjects::ClassObject.new(o1, :Long)
      o3 = CodeObjects::ClassObject.new(o2, :PathName)
      obj = CodeObjects::MethodObject.new(o3, :foo)

      expect(FileUtils).to receive(:mkdir_p).once.with('doc/Really/Long/PathName')

      s = Serializers::FileSystemSerializer.new
      s.serialize(obj, "data")
    end
  end
end
