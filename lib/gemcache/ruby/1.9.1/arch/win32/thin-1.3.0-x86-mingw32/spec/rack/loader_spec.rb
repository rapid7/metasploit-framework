require File.dirname(__FILE__) + '/../spec_helper'

describe Rack::Adapter do
  before do
    @config_ru_path = File.dirname(__FILE__) + '/../../example'
    @rails_path = File.dirname(__FILE__) + '/../rails_app'
  end
  
  it "should load Rack app from config" do
    Rack::Adapter.load(@config_ru_path + '/config.ru').class.should == Proc
  end
  
  it "should guess Rack app from dir" do
    Rack::Adapter.guess(@config_ru_path).should == :rack
  end
  
  it "should guess rails app from dir" do
    Rack::Adapter.guess(@rails_path).should == :rails
  end
  
  it "should return nil when can't guess from dir" do
    proc { Rack::Adapter.guess('.') }.should raise_error(Rack::AdapterNotFound)
  end
  
  it "should load Rack adapter" do
    Rack::Adapter.for(:rack, :chdir => @config_ru_path).class.should == Proc
  end
  
  it "should load Rails adapter" do
    Rack::Adapter::Rails.should_receive(:new)
    Rack::Adapter.for(:rails, :chdir => @rails_path)
  end
  
  it "should load File adapter" do
    Rack::File.should_receive(:new)
    Rack::Adapter.for(:file)
  end
  
  it "should raise error when adapter can't be found" do
    proc { Rack::Adapter.for(:fart, {}) }.should raise_error(Rack::AdapterNotFound)
  end
end