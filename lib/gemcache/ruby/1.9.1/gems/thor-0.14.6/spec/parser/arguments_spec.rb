require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/parser'

describe Thor::Arguments do
  def create(opts={})
    arguments = opts.map do |type, default|
      Thor::Argument.new(type.to_s, nil, default.nil?, type, default)
    end

    arguments.sort!{ |a,b| b.name <=> a.name }
    @opt = Thor::Arguments.new(arguments)
  end

  def parse(*args)
    @opt.parse(args)
  end

  describe "#parse" do
    it "parses arguments in the given order" do
      create :string => nil, :numeric => nil
      parse("name", "13")["string"].should == "name"
      parse("name", "13")["numeric"].should == 13
    end

    it "accepts hashes" do
      create :string => nil, :hash => nil
      parse("product", "title:string", "age:integer")["string"].should == "product"
      parse("product", "title:string", "age:integer")["hash"].should == { "title" => "string", "age" => "integer"}
    end

    it "accepts arrays" do
      create :string => nil, :array => nil
      parse("product", "title", "age")["string"].should == "product"
      parse("product", "title", "age")["array"].should == %w(title age)
    end

    describe "with no inputs" do
      it "and no arguments returns an empty hash" do
        create
        parse.should == {}
      end

      it "and required arguments raises an error" do
        create :string => nil, :numeric => nil
        lambda { parse }.should raise_error(Thor::RequiredArgumentMissingError, "No value provided for required arguments 'string', 'numeric'")
      end

      it "and default arguments returns default values" do
        create :string => "name", :numeric => 13
        parse.should == { "string" => "name", "numeric" => 13 }
      end
    end

    it "returns the input if it's already parsed" do
      create :string => nil, :hash => nil, :array => nil, :numeric => nil
      parse("", 0, {}, []).should == { "string" => "", "numeric" => 0, "hash" => {}, "array" => [] }
    end

    it "returns the default value if none is provided" do
      create :string => "foo", :numeric => 3.0
      parse("bar").should == { "string" => "bar", "numeric" => 3.0 }
    end
  end
end
