require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/parser'

describe Thor::Option do
  def parse(key, value)
    Thor::Option.parse(key, value)
  end

  def option(name, options={})
    @option ||= Thor::Option.new(name, options)
  end

  describe "#parse" do

    describe "with value as a symbol" do
      describe "and symbol is a valid type" do
        it "has type equals to the symbol" do
          parse(:foo, :string).type.should == :string
          parse(:foo, :numeric).type.should == :numeric
        end

        it "has not default value" do
          parse(:foo, :string).default.should be_nil
          parse(:foo, :numeric).default.should be_nil
        end
      end

      describe "equals to :required" do
        it "has type equals to :string" do
          parse(:foo, :required).type.should == :string
        end

        it "has no default value" do
          parse(:foo, :required).default.should be_nil
        end
      end

      describe "and symbol is not a reserved key" do
        it "has type equals to :string" do
          parse(:foo, :bar).type.should == :string
        end

        it "has no default value" do
          parse(:foo, :bar).default.should be_nil
        end
      end
    end

    describe "with value as hash" do
      it "has default type :hash" do
        parse(:foo, :a => :b).type.should == :hash
      end

      it "has default value equals to the hash" do
        parse(:foo, :a => :b).default.should == { :a => :b }
      end
    end

    describe "with value as array" do
      it "has default type :array" do
        parse(:foo, [:a, :b]).type.should == :array
      end

      it "has default value equals to the array" do
        parse(:foo, [:a, :b]).default.should == [:a, :b]
      end
    end

    describe "with value as string" do
      it "has default type :string" do
        parse(:foo, "bar").type.should == :string
      end

      it "has default value equals to the string" do
        parse(:foo, "bar").default.should == "bar"
      end
    end

    describe "with value as numeric" do
      it "has default type :numeric" do
        parse(:foo, 2.0).type.should == :numeric
      end

      it "has default value equals to the numeric" do
        parse(:foo, 2.0).default.should == 2.0
      end
    end

    describe "with value as boolean" do
      it "has default type :boolean" do
        parse(:foo, true).type.should == :boolean
        parse(:foo, false).type.should == :boolean
      end

      it "has default value equals to the boolean" do
        parse(:foo, true).default.should == true
        parse(:foo, false).default.should == false
      end
    end

    describe "with key as a symbol" do
      it "sets the name equals to the key" do
        parse(:foo, true).name.should == "foo"
      end
    end

    describe "with key as an array" do
      it "sets the first items in the array to the name" do
        parse([:foo, :bar, :baz], true).name.should == "foo"
      end

      it "sets all other items as aliases" do
        parse([:foo, :bar, :baz], true).aliases.should == [:bar, :baz]
      end
    end
  end

  it "returns the switch name" do
    option("foo").switch_name.should == "--foo"
    option("--foo").switch_name.should == "--foo"
  end

  it "returns the human name" do
    option("foo").human_name.should == "foo"
    option("--foo").human_name.should == "foo"
  end

  it "converts underscores to dashes" do
    option("foo_bar").switch_name.should == "--foo-bar"
  end

  it "can be required and have default values" do
    option = option("foo", :required => true, :type => :string, :default => "bar")
    option.default.should == "bar"
    option.should be_required
  end

  it "cannot be required and have type boolean" do
    lambda {
      option("foo", :required => true, :type => :boolean)
    }.should raise_error(ArgumentError, "An option cannot be boolean and required.")
  end

  it "allows type predicates" do
    parse(:foo, :string).should be_string
    parse(:foo, :boolean).should be_boolean
    parse(:foo, :numeric).should be_numeric
  end

  it "raises an error on method missing" do
    lambda {
      parse(:foo, :string).unknown?
    }.should raise_error(NoMethodError)
  end

  describe "#usage" do

    it "returns usage for string types" do
      parse(:foo, :string).usage.should == "[--foo=FOO]"
    end

    it "returns usage for numeric types" do
      parse(:foo, :numeric).usage.should == "[--foo=N]"
    end

    it "returns usage for array types" do
      parse(:foo, :array).usage.should == "[--foo=one two three]"
    end

    it "returns usage for hash types" do
      parse(:foo, :hash).usage.should == "[--foo=key:value]"
    end

    it "returns usage for boolean types" do
      parse(:foo, :boolean).usage.should == "[--foo]"
    end

    it "uses padding when no aliases is given" do
      parse(:foo, :boolean).usage(4).should == "    [--foo]"
    end

    it "uses banner when supplied" do
      option(:foo, :required => false, :type => :string, :banner => "BAR").usage.should == "[--foo=BAR]"
    end

    it "checkes when banner is an empty string" do
      option(:foo, :required => false, :type => :string, :banner => "").usage.should == "[--foo]"
    end

    describe "with required values" do
      it "does not show the usage between brackets" do
        parse(:foo, :required).usage.should == "--foo=FOO"
      end
    end

    describe "with aliases" do
      it "does not show the usage between brackets" do
        parse([:foo, "-f", "-b"], :required).usage.should == "-f, -b, --foo=FOO"
      end
    end
  end
end
