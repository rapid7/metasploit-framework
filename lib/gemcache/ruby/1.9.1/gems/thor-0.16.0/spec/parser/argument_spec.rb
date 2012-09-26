require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/parser'

describe Thor::Argument do

  def argument(name, options={})
    @argument ||= Thor::Argument.new(name, options)
  end

  describe "errors" do
    it "raises an error if name is not supplied" do
      lambda {
        argument(nil)
      }.should raise_error(ArgumentError, "Argument name can't be nil.")
    end

    it "raises an error if type is unknown" do
      lambda {
        argument(:task, :type => :unknown)
      }.should raise_error(ArgumentError, "Type :unknown is not valid for arguments.")
    end

    it "raises an error if argument is required and have default values" do
      lambda {
        argument(:task, :type => :string, :default => "bar", :required => true)
      }.should raise_error(ArgumentError, "An argument cannot be required and have default value.")
    end

    it "raises an error if enum isn't an array" do
      lambda {
        argument(:task, :type => :string, :enum => "bar")
      }.should raise_error(ArgumentError, "An argument cannot have an enum other than an array.")
    end
  end

  describe "#usage" do
    it "returns usage for string types" do
      argument(:foo, :type => :string).usage.should == "FOO"
    end

    it "returns usage for numeric types" do
      argument(:foo, :type => :numeric).usage.should == "N"
    end

    it "returns usage for array types" do
      argument(:foo, :type => :array).usage.should == "one two three"
    end

    it "returns usage for hash types" do
      argument(:foo, :type => :hash).usage.should == "key:value"
    end
  end
end
