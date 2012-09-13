
require File.dirname(__FILE__) + '/spec_helper'

describe Agent do
  before :each do
    @agent = Agent.new 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_4; en-us) AppleWebKit/528.4+ (KHTML, like Gecko) Version/4.0dp1 Safari/526.11.2'
  end
  
  describe "#initialize" do
    it "should allow a user agent string to be passed" do
      Agent.new('foo').string.should == 'foo'
    end
  end
  
  describe "#os" do
    it "should return operating system symbol" do
      @agent.os.should == :'OS X 10.5'
    end
  end
  
  describe "#engine" do
    it "should return engine symbol" do
      @agent.engine.should == :webkit
    end
  end
  
  describe "#engine_version" do
    it "should return engine version" do
      @agent.engine_version.should == '528.4'
    end
  end
  
  describe "#to_s" do
    it "should return the user agent string" do
      @agent.to_s.should == @agent.string
    end
  end
  
  describe "#inspect" do
    it "should return string presenting the engine, os, version, etc" do
      @agent.inspect.should == '#<Agent:Safari version:"4.0dp1" engine:"webkit:528.4" os:"OS X 10.5">'
    end
  end
  
  describe "#name" do
    it "should return the agent name symbol" do
      @agent.name.should == :'Safari'
    end
  end
  
  describe "#==" do
    it "should be equal when the user agent strings are the same" do
      a = Agent.new 'foo'
      b = Agent.new 'foo'
      a.should == b
    end
    
    it "should not be equal when user agent strings are different" do
      a = Agent.new 'foo'
      b = Agent.new 'bar'
      a.should_not == b
    end
  end
end