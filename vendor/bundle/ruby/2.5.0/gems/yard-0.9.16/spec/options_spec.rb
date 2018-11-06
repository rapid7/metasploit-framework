# frozen_string_literal: true

RSpec.describe YARD::Options do
  class FooOptions < YARD::Options
    attr_accessor :foo
    def initialize; self.foo = "abc" end
  end

  describe ".default_attr" do
    it "allows default attributes to be defined with symbols" do
      class DefaultOptions1 < YARD::Options
        default_attr :foo, 'HELLO'
      end
      o = DefaultOptions1.new
      o.reset_defaults
      expect(o.foo).to eq 'HELLO'
    end

    it "calls lambda if value is a Proc" do
      class DefaultOptions2 < YARD::Options
        default_attr :foo, lambda { 100 }
      end
      o = DefaultOptions2.new
      o.reset_defaults
      expect(o.foo).to eq 100
    end
  end

  describe "#reset_defaults" do
    it "does not define defaults until reset is called" do
      class ResetDefaultOptions1 < YARD::Options
        default_attr :foo, 'FOO'
      end
      expect(ResetDefaultOptions1.new.foo).to be nil
      o = ResetDefaultOptions1.new
      o.reset_defaults
      expect(o.foo).to eq 'FOO'
    end

    it "uses defaults from superclass as well" do
      class ResetDefaultOptions2 < YARD::Options
        default_attr :foo, 'FOO'
      end
      class ResetDefaultOptions3 < ResetDefaultOptions2
      end
      o = ResetDefaultOptions3.new
      o.reset_defaults
      expect(o.foo).to eq 'FOO'
    end
  end

  describe "#delete" do
    it "deletes an option" do
      o = FooOptions.new
      o.delete(:foo)
      expect(o.to_hash).to eq({})
    end

    it "does not error if an option is deleted that does not exist" do
      o = FooOptions.new
      o.delete(:foo)
      o.delete(:foo)
      expect(o.to_hash).to eq({})
    end
  end

  describe "#[]" do
    it "handles getting option values using hash syntax" do
      expect(FooOptions.new[:foo]).to eq "abc"
    end
  end

  describe "#[]=" do
    it "handles setting options using hash syntax" do
      o = FooOptions.new
      o[:foo] = "xyz"
      expect(o[:foo]).to eq "xyz"
    end

    it "allows setting of unregistered keys" do
      o = FooOptions.new
      o[:bar] = "foo"
      expect(o[:bar]).to eq "foo"
    end
  end

  describe "#method_missing" do
    it "allows setting of unregistered keys" do
      o = FooOptions.new
      o.bar = 'foo'
      expect(o.bar).to eq 'foo'
    end

    it "allows getting values of unregistered keys (return nil)" do
      expect(FooOptions.new.bar).to be nil
    end

    it "prints debugging messages about unregistered keys" do
      expect(log).to receive(:debug).with("Attempting to access unregistered key bar on FooOptions")
      FooOptions.new.bar
      expect(log).to receive(:debug).with("Attempting to set unregistered key bar on FooOptions")
      FooOptions.new.bar = 1
    end
  end

  describe "#update" do
    it "allows updating of options" do
      expect(FooOptions.new.update(:foo => "xyz").foo).to eq "xyz"
    end

    it "does not ignore keys with no setter (OpenStruct behaviour)" do
      o = FooOptions.new
      o.update(:bar => "xyz")
      expect(o.to_hash).to eq(:foo => "abc", :bar => "xyz")
    end
  end

  describe "#merge" do
    it "updates a new object" do
      o = FooOptions.new
      expect(o.merge(:foo => "xyz").object_id).not_to eq o.object_id
      expect(o.merge(:foo => "xyz").to_hash).to eq(:foo => "xyz")
    end

    it "adds in values from original object" do
      o = FooOptions.new
      o.update(:bar => "foo")
      expect(o.merge(:baz => 1).to_hash).to eq(:foo => "abc", :bar => "foo", :baz => 1)
    end
  end

  describe "#to_hash" do
    it "converts all instance variables and symbolized keys" do
      class ToHashOptions1 < YARD::Options
        attr_accessor :foo, :bar, :baz
        def initialize; @foo = 1; @bar = 2; @baz = "hello" end
      end
      o = ToHashOptions1.new
      hash = o.to_hash
      expect(hash.keys).to include(:foo, :bar, :baz)
      expect(hash[:foo]).to eq 1
      expect(hash[:bar]).to eq 2
      expect(hash[:baz]).to eq "hello"
    end

    it "uses accessor when converting values to hash" do
      class ToHashOptions2 < YARD::Options
        def initialize; @foo = 1 end
        def foo; "HELLO#{@foo}" end
      end
      o = ToHashOptions2.new
      expect(o.to_hash).to eq(:foo => "HELLO1")
    end

    it "ignores ivars with no accessor" do
      class ToHashOptions3 < YARD::Options
        attr_accessor :foo
        def initialize; @foo = 1; @bar = "NOIGNORE" end
      end
      o = ToHashOptions3.new
      expect(o.to_hash).to eq(:foo => 1, :bar => "NOIGNORE")
    end
  end

  describe "#tap" do
    it "supports #tap(&block) (even in 1.8.6)" do
      o = FooOptions.new.tap {|obj| obj.foo = :BAR }
      expect(o.to_hash).to eq(:foo => :BAR)
    end
  end
end
