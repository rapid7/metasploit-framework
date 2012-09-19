require 'spec_helper'

describe ChunkyPNG do
  
  it "should have a VERSION constant" do
    ChunkyPNG.const_defined?('VERSION').should be_true
  end
end
