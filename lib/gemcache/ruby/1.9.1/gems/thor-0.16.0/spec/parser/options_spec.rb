require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/parser'

describe Thor::Options do
  def create(opts, defaults={})
    opts.each do |key, value|
      opts[key] = Thor::Option.parse(key, value) unless value.is_a?(Thor::Option)
    end

    @opt = Thor::Options.new(opts, defaults)
  end

  def parse(*args)
    @opt.parse(args.flatten)
  end

  def check_unknown!
    @opt.check_unknown!
  end

  describe "#to_switches" do
    it "turns true values into a flag" do
      Thor::Options.to_switches(:color => true).should == "--color"
    end

    it "ignores nil" do
      Thor::Options.to_switches(:color => nil).should == ""
    end

    it "ignores false" do
      Thor::Options.to_switches(:color => false).should == ""
    end

    it "writes --name value for anything else" do
      Thor::Options.to_switches(:format => "specdoc").should == '--format "specdoc"'
    end

    it "joins several values" do
      switches = Thor::Options.to_switches(:color => true, :foo => "bar").split(' ').sort
      switches.should == ['"bar"', "--color", "--foo"]
    end

    it "accepts arrays" do
      Thor::Options.to_switches(:count => [1,2,3]).should == "--count 1 2 3"
    end

    it "accepts hashes" do
      Thor::Options.to_switches(:count => {:a => :b}).should == "--count a:b"
    end

    it "accepts underscored options" do
      Thor::Options.to_switches(:under_score_option => "foo bar").should == '--under_score_option "foo bar"'
    end

  end

  describe "#parse" do
    it "allows multiple aliases for a given switch" do
      create ["--foo", "--bar", "--baz"] => :string
      parse("--foo", "12")["foo"].should == "12"
      parse("--bar", "12")["foo"].should == "12"
      parse("--baz", "12")["foo"].should == "12"
    end

    it "allows custom short names" do
      create "-f" => :string
      parse("-f", "12").should == {"f" => "12"}
    end

    it "allows custom short-name aliases" do
      create ["--bar", "-f"] => :string
      parse("-f", "12").should == {"bar" => "12"}
    end

    it "accepts conjoined short switches" do
      create ["--foo", "-f"] => true, ["--bar", "-b"] => true, ["--app", "-a"] => true
      opts = parse("-fba")
      opts["foo"].should be_true
      opts["bar"].should be_true
      opts["app"].should be_true
    end

    it "accepts conjoined short switches with input" do
      create ["--foo", "-f"] => true, ["--bar", "-b"] => true, ["--app", "-a"] => :required
      opts = parse "-fba", "12"
      opts["foo"].should be_true
      opts["bar"].should be_true
      opts["app"].should == "12"
    end

    it "returns the default value if none is provided" do
      create :foo => "baz", :bar => :required
      parse("--bar", "boom")["foo"].should == "baz"
    end

    it "returns the default value from defaults hash to required arguments" do
      create Hash[:bar => :required], Hash[:bar => "baz"]
      parse["bar"].should == "baz"
    end

    it "gives higher priority to defaults given in the hash" do
      create Hash[:bar => true], Hash[:bar => false]
      parse["bar"].should == false
    end

    it "raises an error for unknown switches" do
      create :foo => "baz", :bar => :required
      parse("--bar", "baz", "--baz", "unknown")
      lambda { check_unknown! }.should raise_error(Thor::UnknownArgumentError, "Unknown switches '--baz'")
    end

    it "skips leading non-switches" do
      create(:foo => "baz")

      parse("asdf", "--foo", "bar").should == {"foo" => "bar"}
    end

    it "correctly recognizes things that look kind of like options, but aren't, as not options" do
      create(:foo => "baz")
      parse("--asdf---asdf", "baz", "--foo", "--asdf---dsf--asdf").should == {"foo" => "--asdf---dsf--asdf"}
      check_unknown!
    end

    it "accepts underscores in commandline args hash for boolean" do
      create :foo_bar => :boolean
      parse("--foo_bar")["foo_bar"].should == true
      parse("--no_foo_bar")["foo_bar"].should == false
    end

    it "accepts underscores in commandline args hash for strings" do
      create :foo_bar => :string, :baz_foo => :string
      parse("--foo_bar", "baz")["foo_bar"].should == "baz"
      parse("--baz_foo", "foo bar")["baz_foo"].should == "foo bar"
    end

    describe "with no input" do
      it "and no switches returns an empty hash" do
        create({})
        parse.should == {}
      end

      it "and several switches returns an empty hash" do
        create "--foo" => :boolean, "--bar" => :string
        parse.should == {}
      end

      it "and a required switch raises an error" do
        create "--foo" => :required
        lambda { parse }.should raise_error(Thor::RequiredArgumentMissingError, "No value provided for required options '--foo'")
      end
    end

    describe "with one required and one optional switch" do
      before do
        create "--foo" => :required, "--bar" => :boolean
      end

      it "raises an error if the required switch has no argument" do
        lambda { parse("--foo") }.should raise_error(Thor::MalformattedArgumentError)
      end

      it "raises an error if the required switch isn't given" do
        lambda { parse("--bar") }.should raise_error(Thor::RequiredArgumentMissingError)
      end

      it "raises an error if the required switch is set to nil" do
        lambda { parse("--no-foo") }.should raise_error(Thor::RequiredArgumentMissingError)
      end

      it "does not raises an error if the required option has a default value" do
        options = {:required => true, :type => :string, :default => "baz"}
        create :foo => Thor::Option.new("foo", options), :bar => :boolean
        lambda { parse("--bar") }.should_not raise_error
      end
    end

    describe "with :string type" do
      before do
        create ["--foo", "-f"] => :required
      end

      it "accepts a switch <value> assignment" do
        parse("--foo", "12")["foo"].should == "12"
      end

      it "accepts a switch=<value> assignment" do
        parse("-f=12")["foo"].should == "12"
        parse("--foo=12")["foo"].should == "12"
        parse("--foo=bar=baz")["foo"].should == "bar=baz"
      end

      it "must accept underscores switch=value assignment" do
        create :foo_bar => :required
        parse("--foo_bar=http://example.com/under_score/")["foo_bar"].should == "http://example.com/under_score/"
      end

      it "accepts a --no-switch format" do
        create "--foo" => "bar"
        parse("--no-foo")["foo"].should be_nil
      end

      it "does not consume an argument for --no-switch format" do
        create "--cheese" => :string
        parse('burger', '--no-cheese', 'fries')["cheese"].should be_nil
      end

      it "accepts a --switch format on non required types" do
        create "--foo" => :string
        parse("--foo")["foo"].should == "foo"
      end

      it "accepts a --switch format on non required types with default values" do
        create "--baz" => :string, "--foo" => "bar"
        parse("--baz", "bang", "--foo")["foo"].should == "bar"
      end

      it "overwrites earlier values with later values" do
        parse("--foo=bar", "--foo", "12")["foo"].should == "12"
        parse("--foo", "12", "--foo", "13")["foo"].should == "13"
      end
    end

    describe "with :boolean type" do
      before do
        create "--foo" => false
      end

      it "accepts --opt assignment" do
        parse("--foo")["foo"].should == true
        parse("--foo", "--bar")["foo"].should == true
      end

      it "uses the default value if no switch is given" do
        parse("")["foo"].should == false
      end

      it "accepts --opt=value assignment" do
        parse("--foo=true")["foo"].should == true
        parse("--foo=false")["foo"].should == false
      end

      it "accepts --[no-]opt variant, setting false for value" do
        parse("--no-foo")["foo"].should == false
      end

      it "accepts --[skip-]opt variant, setting false for value" do
        parse("--skip-foo")["foo"].should == false
      end

      it "will prefer 'no-opt' variant over inverting 'opt' if explicitly set" do
        create "--no-foo" => true
        parse("--no-foo")["no-foo"].should == true
      end

      it "will prefer 'skip-opt' variant over inverting 'opt' if explicitly set" do
        create "--skip-foo" => true
        parse("--skip-foo")["skip-foo"].should == true
      end

      it "accepts inputs in the human name format" do
        create :foo_bar => :boolean
        parse("--foo-bar")["foo_bar"].should == true
        parse("--no-foo-bar")["foo_bar"].should == false
        parse("--skip-foo-bar")["foo_bar"].should == false
      end

      it "doesn't eat the next part of the param" do
        create :foo => :boolean
        parse("--foo", "bar").should == {"foo" => true}
        @opt.remaining.should == ["bar"]
      end
    end

    describe "with :hash type" do
      before do
        create "--attributes" => :hash
      end

      it "accepts a switch=<value> assignment" do
        parse("--attributes=name:string", "age:integer")["attributes"].should == {"name" => "string", "age" => "integer"}
      end

      it "accepts a switch <value> assignment" do
        parse("--attributes", "name:string", "age:integer")["attributes"].should == {"name" => "string", "age" => "integer"}
      end

      it "must not mix values with other switches" do
        parse("--attributes", "name:string", "age:integer", "--baz", "cool")["attributes"].should == {"name" => "string", "age" => "integer"}
      end
    end

    describe "with :array type" do
      before do
        create "--attributes" => :array
      end

      it "accepts a switch=<value> assignment" do
        parse("--attributes=a", "b", "c")["attributes"].should == ["a", "b", "c"]
      end

      it "accepts a switch <value> assignment" do
        parse("--attributes", "a", "b", "c")["attributes"].should == ["a", "b", "c"]
      end

      it "must not mix values with other switches" do
        parse("--attributes", "a", "b", "c", "--baz", "cool")["attributes"].should == ["a", "b", "c"]
      end
    end

    describe "with :numeric type" do
      before do
        create "n" => :numeric, "m" => 5
      end

      it "accepts a -nXY assignment" do
        parse("-n12")["n"].should == 12
      end

      it "converts values to numeric types" do
        parse("-n", "3", "-m", ".5").should == {"n" => 3, "m" => 0.5}
      end

      it "raises error when value isn't numeric" do
        lambda { parse("-n", "foo") }.should raise_error(Thor::MalformattedArgumentError,
          "Expected numeric value for '-n'; got \"foo\"")
      end
    end

  end
end
