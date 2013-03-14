require 'spec_helper'

describe Spork::AppFramework::Unknown do
  it "requires bootstrapping" do
    Spork::AppFramework::Unknown.new.bootstrap_required?.should == true
  end
  
  it "has no known entry point" do
    Spork::AppFramework::Unknown.new.entry_point.should be_nil
  end
end

