require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/core_ext/hash_with_indifferent_access'

describe Thor::CoreExt::HashWithIndifferentAccess do
  before(:each) do
    @hash = Thor::CoreExt::HashWithIndifferentAccess.new :foo => 'bar', 'baz' => 'bee', :force => true
  end

  it "has values accessible by either strings or symbols" do
    @hash['foo'].should == 'bar'
    @hash[:foo].should  == 'bar'

    @hash.values_at(:foo, :baz).should == ['bar', 'bee']
    @hash.delete(:foo).should == 'bar'
  end

  it "handles magic boolean predicates" do
    @hash.force?.should be_true
    @hash.foo?.should be_true
    @hash.nothing?.should be_false
  end

  it "handles magic comparisions" do
    @hash.foo?('bar').should be_true
    @hash.foo?('bee').should be_false
  end

  it "maps methods to keys" do
    @hash.foo.should == @hash['foo']
  end

  it "merges keys independent if they are symbols or strings" do
    @hash.merge!('force' => false, :baz => "boom")
    @hash[:force].should == false
    @hash[:baz].should == "boom"
  end

  it "creates a new hash by merging keys independent if they are symbols or strings" do
    other = @hash.merge('force' => false, :baz => "boom")
    other[:force].should == false
    other[:baz].should == "boom"
  end
end
