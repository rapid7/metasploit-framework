# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::NamespaceObject do
  before { Registry.clear }

  describe "#child" do
    it "returns the object matching the name passed in if argument is a Symbol" do
      obj = NamespaceObject.new(nil, :YARD)
      other = NamespaceObject.new(obj, :Other)
      expect(obj.child(:Other)).to eq other
      expect(obj.child('Other')).to eq other
    end

    it "looks for attributes matching the object if the argument is a Hash" do
      obj = NamespaceObject.new(nil, :YARD)
      NamespaceObject.new(obj, :NotOther)
      other = NamespaceObject.new(obj, :Other)
      other.somevalue = 2
      expect(obj.child(:somevalue => 2)).to eq other
    end
  end

  describe "#meths" do
    it "returns #meths even if parent is a Proxy" do
      obj = NamespaceObject.new(P(:String), :YARD)
      expect(obj.meths).to be_empty
    end

    it "does not list included methods that are already defined in the namespace using #meths" do
      a = ModuleObject.new(nil, :Mod1)
      ameth = MethodObject.new(a, :testing)
      b = ModuleObject.new(nil, :Mod2)
      bmeth = MethodObject.new(b, :foo)
      c = NamespaceObject.new(nil, :YARD)
      cmeth = MethodObject.new(c, :testing)
      cmeth2 = MethodObject.new(c, :foo)
      c.instance_mixins << a
      c.class_mixins << b

      meths = c.meths
      expect(meths).to include(bmeth)
      expect(meths).to include(cmeth)
      expect(meths).to include(cmeth2)
      expect(meths).not_to include(ameth)

      meths = c.included_meths
      expect(meths).to include(bmeth)
      expect(meths).not_to include(ameth)
      expect(meths).not_to include(cmeth)
      expect(meths).not_to include(cmeth2)
    end
  end

  describe "#included_meths" do
    it "lists methods mixed into the class scope as class methods" do
      b = ModuleObject.new(nil, :Mod2)
      bmeth = MethodObject.new(b, :foo)
      bmeth2 = MethodObject.new(b, :foo2)
      c = NamespaceObject.new(nil, :YARD)
      c.class_mixins << b

      [bmeth, bmeth2].each {|o| expect(o.scope).to eq :instance }
      meths = c.included_meths(:scope => :class)
      meths.each {|o| expect(o.scope).to eq :class }
    end

    it "does not list methods overridden by another included module" do
      a = ModuleObject.new(nil, :Mod)
      ameth = MethodObject.new(a, :testing)
      b = ModuleObject.new(nil, :Mod2)
      bmeth = MethodObject.new(b, :testing)
      c = NamespaceObject.new(nil, :YARD)
      c.instance_mixins.unshift a
      c.instance_mixins.unshift b
      c.class_mixins.unshift b
      c.class_mixins.unshift a

      meths = c.included_meths(:scope => :instance)
      expect(meths).not_to include(ameth)
      expect(meths).to include(bmeth)

      meths = c.included_meths(:scope => :class)
      expect(meths).to include(ameth)
      expect(meths).not_to include(bmeth)
    end
  end

  describe "#class_attributes" do
    it "lists class attributes" do
      a = NamespaceObject.new(nil, :Mod)
      a.attributes[:instance][:a] = {:read => MethodObject.new(a, :a), :write => nil}
      a.attributes[:instance][:b] = {:read => MethodObject.new(a, :b), :write => nil}
      a.attributes[:class][:a] = {:read => MethodObject.new(a, :a, :class), :write => nil}
      expect(a.class_attributes.keys).to include(:a)
      expect(a.class_attributes.keys).not_to include(:b)
    end
  end

  describe "#instance_attributes" do
    it "lists instance attributes" do
      a = NamespaceObject.new(nil, :Mod)
      a.attributes[:instance][:a] = {:read => MethodObject.new(a, :a), :write => nil}
      a.attributes[:instance][:b] = {:read => MethodObject.new(a, :b), :write => nil}
      a.attributes[:class][:a] = {:read => MethodObject.new(a, :a, :class), :write => nil}
      expect(a.instance_attributes.keys).to include(:a)
      expect(a.instance_attributes.keys).to include(:b)
    end
  end

  describe "#constants/#included_constants" do
    before do
      Registry.clear

      YARD.parse_string <<-eof
        module A
          CONST1 = 1
          CONST2 = 2
        end

        module B
          CONST2 = -2
          CONST3 = -3
        end

        class C
          CONST3 = 3
          CONST4 = 4

          include A
          include B
        end
      eof
    end

    it "lists all included constants by default" do
      consts = P(:C).constants
      expect(consts).to include(P('A::CONST1'))
      expect(consts).to include(P('C::CONST4'))
    end

    it "allows :included to be set to false to ignore included constants" do
      consts = P(:C).constants(:included => false)
      expect(consts).not_to include(P('A::CONST1'))
      expect(consts).to include(P('C::CONST4'))
    end

    it "does not list an included constant if it is defined in the object" do
      consts = P(:C).constants
      expect(consts).to include(P('C::CONST3'))
      expect(consts).not_to include(P('B::CONST3'))
    end

    it "does not list an included constant if it is shadowed by another included constant" do
      consts = P(:C).included_constants
      expect(consts).to include(P('B::CONST2'))
      expect(consts).not_to include(P('A::CONST2'))
    end
  end

  describe "#included_meths" do
    it "returns all included methods with :all = true" do
      YARD.parse_string <<-eof
        module B; def foo; end end
        module C; def bar; end end
        class A; include B; include C; def foo; end; def bar; end end
      eof
      expect(Registry.at('A').included_meths(:all => true)).to eq [P('C#bar'), P('B#foo')]
    end
  end
end
