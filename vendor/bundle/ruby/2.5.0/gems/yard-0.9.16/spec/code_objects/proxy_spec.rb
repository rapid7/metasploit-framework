# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::Proxy do
  before { Registry.clear }

  it "returns the object if it's in the Registry" do
    ModuleObject.new(:root, :YARD)
    proxyobj = P(:root, :YARD)
    expect(proxyobj.type).to eq :module
    expect(Proxy === proxyobj).to be false
  end

  it "handles complex string namespaces" do
    ModuleObject.new(:root, :A)
    ModuleObject.new(P(nil, :A), :B)
    expect(P(:root, "A::B")).to be_instance_of(ModuleObject)
  end

  it "does not return true to Proxy === obj if obj is a Proxy class holding a resolved object" do
    expect(Proxy === P(:root, 'a')).to be true
    expect(Proxy === P(:root)).to be false
    MethodObject.new(:root, 'a')
    expect(Proxy === P(:root, 'a')).to be false
    x = Proxy.new(:root, 'a')
    expect(Proxy === x).to be false
  end

  it "returns the object if it's an included Module" do
    yardobj = ModuleObject.new(:root, :YARD)
    pathobj = ClassObject.new(:root, :TestClass)
    pathobj.instance_mixins << yardobj
    expect(P(P(nil, :TestClass), :YARD)).to be_instance_of(ModuleObject)
  end

  it "responds to respond_to?" do
    ClassObject.new(:root, :Object)
    ModuleObject.new(:root, :YARD)
    expect(P(:YARD).respond_to?(:children)).to be true
    expect(P(:NOTYARD).respond_to?(:children)).to be false

    expect(P(:YARD).respond_to?(:initialize)).to be false
    expect(P(:YARD).respond_to?(:initialize, true)).to be true
    expect(P(:NOTYARD).respond_to?(:initialize)).to be false
    expect(P(:NOTYARD).respond_to?(:initialize, true)).to be true
  end

  it "makes itself obvious that it's a proxy" do
    pathobj = P(:root, :YARD)
    expect(pathobj.class).to eq Proxy
    expect(Proxy === pathobj).to be true
  end

  it "pretends it's the object's type if it can resolve" do
    ModuleObject.new(:root, :YARD)
    proxyobj = P(:root, :YARD)
    expect(proxyobj).to be_instance_of(ModuleObject)
  end

  it "handles instance method names" do
    obj = P(nil, '#test')
    expect(obj.name).to eq :test
    expect(obj.path).to eq "#test"
    expect(obj.namespace).to eq Registry.root
  end

  it "handles instance method names under a namespace" do
    pathobj = ModuleObject.new(:root, :YARD)
    obj = P(pathobj, "A::B#test")
    expect(obj.name).to eq :test
    expect(obj.path).to eq "A::B#test"
  end

  it "allows type to be changed" do
    obj = P("InvalidClass")
    expect(obj.type).to eq :proxy
    expect(Proxy === obj).to be true
    obj.type = :class
    expect(obj.type).to eq :class
  end

  it "does NOT retain a type change between Proxy objects" do
    P("InvalidClass").type = :class
    expect(P("InvalidClass").type).to eq :proxy
  end

  it "uses type to ensure resolved object is of intended type" do
    YARD.parse_string <<-eof
      module Foo
        class Bar; end
        def self.Bar; end
      end
    eof
    proxy = Proxy.new(P('Foo'), 'Bar')
    proxy.type = :method
    expect(proxy.path).to eq 'Foo.Bar'
  end

  it "allows type in initializer" do
    expect(Proxy.new(Registry.root, 'Foo', :method).type).to eq :method
    expect(P(Registry.root, 'Foo', :method).type).to eq :method
  end

  it "never equals Registry.root" do
    expect(P("MYPROXY")).not_to eq Registry.root
    expect(P("X::A")).not_to eq Registry.root
  end

  it "resets namespace and name when object is resolved" do
    obj1 = ModuleObject.new(:root, :YARD)
    obj2 = ModuleObject.new(:root, :NOTYARD)
    resolved = Proxy.new(obj2, :YARD)
    expect(resolved).to eq obj1
    expect(resolved.namespace).to eq Registry.root
    expect(resolved.name).to eq :YARD
  end

  it "ensures that the correct object was resolved" do
    foo = ModuleObject.new(:root, :Foo)
    foobar = ModuleObject.new(foo, :Bar)
    ClassObject.new(foo, :Baz)

    # Remember, we're looking for Qux::Bar, not just 'Bar'
    proxy = Proxy.new(foobar, 'Foo::Qux::Bar')
    expect(proxy.type).to eq :proxy

    qux = ModuleObject.new(foo, :Qux)
    ModuleObject.new(qux, :Bar)

    # Now it should resolve
    expect(proxy.type).to eq :module
  end

  it "handles constant names in namespaces" do
    YARD.parse_string <<-eof
      module A; end; B = A
      module B::C; def foo; end end
    eof
    expect(Proxy.new(:root, 'B::C')).to eq Registry.at('A::C')
  end
end
