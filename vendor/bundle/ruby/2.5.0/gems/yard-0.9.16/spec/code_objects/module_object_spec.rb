# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::ModuleObject do
  describe "#meths" do
    before do
      Registry.clear

      # setup the object space:
      #
      #   YARD:module
      #   YARD#foo:method
      #   YARD#foo2:method
      #   YARD#xyz:method
      #   YARD.bar:method
      #   SomeMod#mixmethod
      #   SomeMod#xyz:method
      #
      @yard = ModuleObject.new(:root, :YARD)
      MethodObject.new(@yard, :foo)
      MethodObject.new(@yard, :xyz)
      MethodObject.new(@yard, :foo2) do |o|
        o.visibility = :protected
      end
      MethodObject.new(@yard, :bar, :class) do |o|
        o.visibility = :private
      end
      @other = ModuleObject.new(:root, :SomeMod)
      MethodObject.new(@other, :mixmethod)
      MethodObject.new(@other, :xyz)
      MethodObject.new(@other, :baz, :class)
      @another = ModuleObject.new(:root, :AnotherMod)
      MethodObject.new(@another, :fizz)
      MethodObject.new(@another, :bar)
      MethodObject.new(@another, :fazz, :class)

      @yard.instance_mixins << @other
      @yard.class_mixins << @another
    end

    it "lists all methods (including mixin methods) via #meths" do
      meths = @yard.meths
      expect(meths).to include(P("YARD#foo"))
      expect(meths).to include(P("YARD#foo2"))
      expect(meths).to include(P("YARD.bar"))
      expect(meths).to include(P("SomeMod#mixmethod"))
      expect(meths).to include(P("AnotherMod#fizz"))
    end

    it "allows :visibility to be set" do
      meths = @yard.meths(:visibility => :public)
      expect(meths).not_to include(P("YARD.bar"))
      meths = @yard.meths(:visibility => [:public, :private])
      expect(meths).to include(P("YARD#foo"))
      expect(meths).to include(P("YARD.bar"))
      expect(meths).not_to include(P("YARD#foo2"))
    end

    it "only displays class methods for :scope => :class" do
      meths = @yard.meths(:scope => :class)
      expect(meths).not_to include(P("YARD#foo"))
      expect(meths).not_to include(P("YARD#foo2"))
      expect(meths).not_to include(P("SomeMod#mixmethod"))
      expect(meths).not_to include(P("SomeMod.baz"))
      expect(meths).not_to include(P("AnotherMod#fazz"))
      expect(meths).to include(P("YARD.bar"))
      expect(meths).to include(P("AnotherMod#fizz"))
    end

    it "only displays instance methods for :scope => :class" do
      meths = @yard.meths(:scope => :instance)
      expect(meths).to include(P("YARD#foo"))
      expect(meths).to include(P("YARD#foo2"))
      expect(meths).to include(P("SomeMod#mixmethod"))
      expect(meths).not_to include(P("YARD.bar"))
      expect(meths).not_to include(P("AnotherMod#fizz"))
    end

    it "allows :included to be set" do
      meths = @yard.meths(:included => false)
      expect(meths).not_to include(P("SomeMod#mixmethod"))
      expect(meths).not_to include(P("AnotherMod#fizz"))
      expect(meths).to include(P("YARD#foo"))
      expect(meths).to include(P("YARD#foo2"))
      expect(meths).to include(P("YARD.bar"))
    end

    it "chooses the method defined in the class over an included module" do
      meths = @yard.meths
      expect(meths).not_to include(P("SomeMod#xyz"))
      expect(meths).to include(P("YARD#xyz"))
      expect(meths).not_to include(P("AnotherMod#bar"))
      expect(meths).to include(P("YARD.bar"))

      meths = @other.meths
      expect(meths).to include(P("SomeMod#xyz"))

      meths = @another.meths
      expect(meths).to include(P("AnotherMod#bar"))
    end
  end

  describe "#inheritance_tree" do
    before do
      Registry.clear

      @mod1 = ModuleObject.new(:root, :Mod1)
      @mod2 = ModuleObject.new(:root, :Mod2)
      @mod3 = ModuleObject.new(:root, :Mod3)
      @mod4 = ModuleObject.new(:root, :Mod4)
      @mod5 = ModuleObject.new(:root, :Mod5)

      @mod1.instance_mixins << @mod2
      @mod2.instance_mixins << @mod3
      @mod3.instance_mixins << @mod4
      @mod1.instance_mixins << @mod4

      @proxy = P(:SomeProxyClass)
      @mod5.instance_mixins << @proxy
    end

    it "shows only itself for an inheritance tree without included modules" do
      expect(@mod1.inheritance_tree).to eq [@mod1]
    end

    it "shows proper inheritance tree when modules are included" do
      expect(@mod1.inheritance_tree(true)).to eq [@mod1, @mod2, @mod3, @mod4]
    end

    it "does not list inheritance tree of proxy objects in inheritance tree" do
      expect(@proxy).not_to receive(:inheritance_tree)
      expect(@mod5.instance_mixins).to eq [@proxy]
    end

    it "lists class mixins in inheritance tree" do
      mod = ModuleObject.new(:root, :ClassMethods)
      recvmod = ModuleObject.new(:root, :ReceivingModule)
      recvmod.class_mixins << mod
      expect(recvmod.inheritance_tree(true)).to eq [recvmod, mod]
    end
  end
end
