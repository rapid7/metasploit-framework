# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::MethodObject do
  before do
    Registry.clear
    @yard = ModuleObject.new(:root, :YARD)
  end

  context "for an instance method in the root" do
    it "has a path of testing" do
      meth = MethodObject.new(:root, :testing)
      expect(meth.path).to eq "#testing"
    end
  end

  context "for an instance method in YARD" do
    it "has a path of YARD#testing" do
      meth = MethodObject.new(@yard, :testing)
      expect(meth.path).to eq "YARD#testing"
    end
  end

  context "for a class method in YARD" do
    it "has a path of YARD.testing" do
      meth = MethodObject.new(@yard, :testing, :class)
      expect(meth.path).to eq "YARD.testing"
    end
  end

  context "for a class method added to root namespace" do
    it "has a path of ::testing (note the ::)" do
      meth = MethodObject.new(:root, :testing, :class)
      expect(meth.path).to eq "::testing"
    end
  end

  it "exists in the registry after successful creation" do
    MethodObject.new(@yard, :something, :class)
    expect(Registry.at("YARD.something")).not_to be nil
    expect(Registry.at("YARD#something")).to be nil
    expect(Registry.at("YARD::something")).to be nil
    MethodObject.new(@yard, :somethingelse)
    expect(Registry.at("YARD#somethingelse")).not_to be nil
  end

  it "allows #scope to be changed after creation" do
    obj = MethodObject.new(@yard, :something, :class)
    expect(Registry.at("YARD.something")).not_to be nil
    obj.scope = :instance
    expect(Registry.at("YARD.something")).to be nil
    expect(Registry.at("YARD#something")).not_to be nil
  end

  it "creates object in :class scope if scope is :module" do
    obj = MethodObject.new(@yard, :module_func, :module)
    expect(obj.scope).to eq :class
    expect(obj.visibility).to eq :public
    expect(Registry.at('YARD.module_func')).not_to be nil
  end

  it "creates second private instance method if scope is :module" do
    MethodObject.new(@yard, :module_func, :module)
    obj = Registry.at('YARD#module_func')
    expect(obj).not_to be nil
    expect(obj.visibility).to eq :private
    expect(obj.scope).to eq :instance
  end

  it "yields block to second method if scope is :module" do
    MethodObject.new(@yard, :module_func, :module) do |o|
      o.docstring = 'foo'
    end
    expect(Registry.at('YARD.module_func').docstring).to eq 'foo'
    expect(Registry.at('YARD#module_func').docstring).to eq 'foo'
  end

  describe "#name" do
    it "shows a prefix for an instance method when prefix=true" do
      obj = MethodObject.new(nil, :something)
      expect(obj.name(true)).to eq "#something"
    end

    it "never shows a prefix for a class method" do
      obj = MethodObject.new(nil, :something, :class)
      expect(obj.name).to eq :something
      expect(obj.name(true)).to eq "something"
    end
  end

  describe "#is_attribute?" do
    it "only returns true if attribute is set in namespace for read/write" do
      obj = MethodObject.new(@yard, :foo)
      @yard.attributes[:instance][:foo] = {:read => obj, :write => nil}
      expect(obj.is_attribute?).to be true
      expect(MethodObject.new(@yard, :foo=).is_attribute?).to be false
    end
  end

  describe "#attr_info" do
    it "returns attribute info if namespace is available" do
      obj = MethodObject.new(@yard, :foo)
      @yard.attributes[:instance][:foo] = {:read => obj, :write => nil}
      expect(obj.attr_info).to eq @yard.attributes[:instance][:foo]
    end

    it "returns nil if namespace is proxy" do
      MethodObject.new(P(:ProxyClass), :foo)
      expect(MethodObject.new(@yard, :foo).attr_info).to eq nil
    end

    it "returns nil if meth is not an attribute" do
      expect(MethodObject.new(@yard, :notanattribute).attr_info).to eq nil
    end
  end

  describe "#writer?" do
    it "returns true if method is a writer attribute" do
      obj = MethodObject.new(@yard, :foo=)
      @yard.attributes[:instance][:foo] = {:read => nil, :write => obj}
      expect(obj.writer?).to be true
      expect(MethodObject.new(@yard, :NOTfoo=).writer?).to be false
    end
  end

  describe "#reader?" do
    it "returns true if method is a reader attribute" do
      obj = MethodObject.new(@yard, :foo)
      @yard.attributes[:instance][:foo] = {:read => obj, :write => nil}
      expect(obj.reader?).to be true
      expect(MethodObject.new(@yard, :NOTfoo).reader?).to be false
    end
  end

  describe "#constructor?" do
    before { @class = ClassObject.new(:root, :MyClass) }

    it "marks the #initialize method as constructor" do
      MethodObject.new(@class, :initialize)
    end

    it "does not mark Klass.initialize as constructor" do
      expect(MethodObject.new(@class, :initialize, :class).constructor?).to be false
    end

    it "does not mark module method #initialize as constructor" do
      expect(MethodObject.new(@yard, :initialize).constructor?).to be false
    end
  end

  describe "#overridden_method" do
    before { Registry.clear }

    it "returns overridden method from mixin first" do
      YARD.parse_string(<<-eof)
        module C; def foo; end end
        class A; def foo; end end
        class B < A; include C; def foo; end end
      eof
      expect(Registry.at('B#foo').overridden_method).to eq Registry.at('C#foo')
    end

    it "returns overridden method from superclass" do
      YARD.parse_string(<<-eof)
        class A; def foo; end end
        class B < A; def foo; end end
      eof
      expect(Registry.at('B#foo').overridden_method).to eq Registry.at('A#foo')
    end

    it "returns nil if none is found" do
      YARD.parse_string(<<-eof)
        class A; end
        class B < A; def foo; end end
      eof
      expect(Registry.at('B#foo').overridden_method).to be nil
    end

    it "returns nil if namespace is a proxy" do
      YARD.parse_string "def ARGV.foo; end"
      expect(Registry.at('ARGV.foo').overridden_method).to be nil
    end
  end
end
