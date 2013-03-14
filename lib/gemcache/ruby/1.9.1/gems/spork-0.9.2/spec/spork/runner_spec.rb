require 'spec_helper'

describe Spork::Runner do
  def use_test_server(klass = Spork::TestFramework::RSpec)
    @test_framework = klass.new
    Spork::TestFramework.stub!(:factory).and_return(@test_framework)
  end

  before(:each) do
    @out, @err = StringIO.new, StringIO.new
  end
  
  it "finds a matching server with a prefix" do
    Spork::Runner.new(["rs"], @out, @err).find_test_framework.class.should == Spork::TestFramework::RSpec
  end
  
  it "shows an error message if no matching server was found" do
    Spork::Runner.new(["argle_bargle"], @out, @err).run.should == false
    @err.string.should include(%(Couldn't find a supported test framework that begins with 'argle_bargle'))
  end
  
  it "bootstraps a server when -b is passed in" do
    use_test_server
    @test_framework.should_receive(:bootstrap)
    Spork::Runner.new(['rspec', '-b'], @out, @err).run
  end
  
  it "aborts if it can't preload" do
    use_test_server
    @test_framework.should_receive(:preload).and_return(false)
    Spork::Server.should_not_receive(:run)
    Spork::Runner.new(['rspec'], @out, @err).run
  end
  
  it "runs the server if all is well" do
    use_test_server
    @test_framework.should_receive(:preload).and_return(true)
    Spork::Server.should_receive(:run)
    Spork::Runner.new(['rspec'], @out, @err).run
    @err.string.should include("Using RSpec")
  end
  
  it "outputs a list of supported servers, along with supported asterisk" do
    Spork::Server.stub!(:supported_test_frameworks).and_return([Spork::TestFramework::RSpec, Spork::TestFramework::Cucumber])
    Spork::TestFramework::RSpec.stub!(:available?).and_return(true)
    Spork::TestFramework::Cucumber.stub!(:available?).and_return(false)
    
    Spork::Runner.new(['rspec'], @out, @err).supported_test_frameworks_text.should include("(*) RSpec")
  end
end
