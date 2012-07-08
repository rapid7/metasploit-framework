require 'spec_helper'

describe Spork::AppFramework do
  describe ".detect_framework" do
    it "detects when rails is installed and available" do
      create_file("config/environment.rb", "RAILS_GEM_VERSION = '2.1.0'")
      in_current_dir do
        Spork::AppFramework.detect_framework.short_name.should == "Rails"
      end
    end
  
    it "returns Unknown when no framework known detected" do
      Spork::AppFramework.detect_framework.short_name.should == "Unknown"
    end
  end
end
