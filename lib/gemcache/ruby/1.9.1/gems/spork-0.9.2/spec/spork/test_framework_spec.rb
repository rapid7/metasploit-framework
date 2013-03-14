require 'spec_helper'

describe Spork::TestFramework do

  before(:each) do
    @fake = FakeFramework.new
  end

  describe ".available_test_frameworks" do
    before(:each) do
      Spork::TestFramework.supported_test_frameworks.each { |s| s.stub!(:available?).and_return(false) }
    end

    it "returns a list of all available servers" do
      Spork::TestFramework.available_test_frameworks.should == []
      Spork::TestFramework::RSpec.stub!(:available?).and_return(true)
      Spork::TestFramework.available_test_frameworks.should == [Spork::TestFramework::RSpec]
    end

    it "returns rspec before cucumber when both are available" do
      Spork::TestFramework::RSpec.stub!(:available?).and_return(true)
      Spork::TestFramework::Cucumber.stub!(:available?).and_return(true)
      Spork::TestFramework.available_test_frameworks.should == [Spork::TestFramework::RSpec, Spork::TestFramework::Cucumber]
    end
  end

  describe ".supported_test_frameworks" do
    it "returns all defined servers" do
      Spork::TestFramework.supported_test_frameworks.should include(Spork::TestFramework::RSpec)
      Spork::TestFramework.supported_test_frameworks.should include(Spork::TestFramework::Cucumber)
    end

    it "returns a list of servers matching a case-insensitive prefix" do
      Spork::TestFramework.supported_test_frameworks("rspec").should == [Spork::TestFramework::RSpec]
      Spork::TestFramework.supported_test_frameworks("rs").should == [Spork::TestFramework::RSpec]
      Spork::TestFramework.supported_test_frameworks("cuc").should == [Spork::TestFramework::Cucumber]
    end
  end

  describe ".short_name" do
    it "returns the name of the framework, without the namespace prefix" do
      Spork::TestFramework::Cucumber.short_name.should == "Cucumber"
    end
  end

  describe ".available?" do
    it "returns true when the helper_file exists" do
      FakeFramework.available?.should == false
      create_helper_file(FakeFramework)
      FakeFramework.available?.should == true
    end
  end

  describe ".bootstrapped?" do
    it "recognizes if the helper_file has been bootstrapped" do
      bootstrap_contents = File.read(FakeFramework::BOOTSTRAP_FILE)
      File.stub!(:read).with(@fake.helper_file).and_return("")
      @fake.bootstrapped?.should == false
      File.stub!(:read).with(@fake.helper_file).and_return(bootstrap_contents)
      @fake.bootstrapped?.should == true
    end
  end

  describe ".bootstrap" do
    it "bootstraps a file" do
      create_helper_file
      @fake.bootstrap

      $test_stderr.string.should include("Bootstrapping")
      $test_stderr.string.should include("Edit")
      $test_stderr.string.should include("favorite text editor")

      File.read(@fake.helper_file).should include(File.read(FakeFramework::BOOTSTRAP_FILE))
    end
  end

  describe ".factory" do
    it "defaults to use rspec over cucumber" do
      Spork::TestFramework::RSpec.stub!(:available?).and_return(true)
      Spork::TestFramework::Cucumber.stub!(:available?).and_return(true)
      Spork::TestFramework.factory(STDOUT, STDERR).class.should == Spork::TestFramework::RSpec
    end

    it "defaults to use cucumber when rspec not available" do
      Spork::TestFramework::RSpec.stub!(:available?).and_return(false)
      Spork::TestFramework::Cucumber.stub!(:available?).and_return(true)
      Spork::TestFramework.factory(STDOUT, STDERR).class.should == Spork::TestFramework::Cucumber
    end
  end
end
