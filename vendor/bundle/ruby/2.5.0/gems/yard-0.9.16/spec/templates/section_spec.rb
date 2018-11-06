# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Section do
  include YARD::Templates

  describe "#initialize" do
    it "converts first argument to splat if it is array" do
      s = Section.new(:name, [:foo, :bar])
      expect(s.name).to eq :name
      expect(s[0].name).to eq :foo
      expect(s[1].name).to eq :bar
    end

    it "allows initialization with Section objects" do
      s = Section.new(:name, [:foo, Section.new(:bar)])
      expect(s.name).to eq :name
      expect(s[0]).to eq Section.new(:foo)
      expect(s[1]).to eq Section.new(:bar)
    end

    it "makes a list of sections" do
      s = Section.new(:name, [:foo, [:bar]])
      expect(s).to eq Section.new(:name, Section.new(:foo, Section.new(:bar)))
    end
  end

  describe "#[]" do
    it "uses Array#[] if argument is integer" do
      expect(Section.new(:name, [:foo, :bar])[0].name).to eq :foo
    end

    it "returns new Section object if more than one argument" do
      expect(Section.new(:name, :foo, :bar, :baz)[1, 2]).to eq Section.new(:name, :bar, :baz)
    end

    it "returns new Section object if arg is Range" do
      expect(Section.new(:name, :foo, :bar, :baz)[1..2]).to eq Section.new(:name, :bar, :baz)
    end

    it "looks for section by name if arg is object" do
      expect(Section.new(:name, :foo, :bar, [:baz])[:bar][:baz]).to eq Section.new(:baz)
    end
  end

  describe "#eql?" do
    it "checks for equality of two equal sections" do
      expect(Section.new(:foo, [:a, :b])).to eql(Section.new(:foo, :a, :b))
      expect(Section.new(:foo, [:a, :b])).to eq Section.new(:foo, :a, :b)
    end

    it "is not equal if section names are different" do
      expect(Section.new(:foo, [:a, :b])).not_to eql(Section.new(:bar, :a, :b))
      expect(Section.new(:foo, [:a, :b])).not_to eq Section.new(:bar, :a, :b)
    end
  end

  describe "#==" do
    it "allows comparison to Symbol" do
      expect(Section.new(:foo, 2, 3)).to eq :foo
    end

    it "allows comparison to String" do
      expect(Section.new("foo", 2, 3)).to eq "foo"
    end

    it "allows comparison to Template" do
      t = YARD::Templates::Engine.template!(:xyzzy, '/full/path/xyzzy')
      expect(Section.new(t, 2, 3)).to eq t
    end

    it "allows comparison to Section" do
      expect(Section.new(1, [2, 3])).to eq Section.new(1, 2, 3)
    end

    it "allows comparison to Object" do
      expect(Section.new(1, [2, 3])).to eq 1
    end

    it "allows comparison to Array" do
      expect(Section.new(1, 2, [3])).to eq [1, [2, [3]]]
    end
  end

  describe "#to_a" do
    it "converts Section to regular Array list" do
      arr = Section.new(1, 2, [3, [4]]).to_a
      expect(arr.class).to eq Array
      expect(arr).to eq [1, [2, [3, [4]]]]
    end
  end

  describe "#place" do
    it "places objects as Sections" do
      expect(Section.new(1, 2, 3).place(4).before(3)).to eq [1, [2, 4, 3]]
    end

    it "places objects anywhere inside Section with before/after_any" do
      expect(Section.new(1, 2, [3, [4]]).place(5).after_any(4)).to eq [1, [2, [3, [4, 5]]]]
      expect(Section.new(1, 2, [3, [4]]).place(5).before_any(4)).to eq [1, [2, [3, [5, 4]]]]
    end

    it "allows multiple sections to be placed" do
      expect(Section.new(1, 2, 3).place(4, 5).after(3).to_a).to eq [1, [2, 3, 4, 5]]
      expect(Section.new(1, 2, 3).place(4, [5]).after(3).to_a).to eq [1, [2, 3, 4, [5]]]
    end
  end

  describe "#push" do
    it "pushes objects as Sections" do
      s = Section.new(:foo)
      s.push :bar
      expect(s[0]).to eq Section.new(:bar)
    end

    it "is aliased as #<<" do
      s = Section.new(1)
      s << :index
      expect(s[:index]).to be_a(Section)
    end
  end

  describe "#unshift" do
    it "unshifts objects as Sections" do
      s = Section.new(:foo)
      s.unshift :bar
      expect(s[0]).to eq Section.new(:bar)
    end
  end

  describe "#any" do
    it "finds item inside sections" do
      s = Section.new(:foo, Section.new(:bar, Section.new(:bar)))
      s.any(:bar).push(:baz)
      expect(s.to_a).to eq [:foo, [:bar, [:bar, :baz]]]
    end

    it "finds item in any deeply nested set of sections" do
      s = Section.new(:foo, Section.new(:bar, Section.new(:baz)))
      s.any(:baz).push(:qux)
      expect(s.to_a).to eq [:foo, [:bar, [:baz, [:qux]]]]
    end
  end
end
