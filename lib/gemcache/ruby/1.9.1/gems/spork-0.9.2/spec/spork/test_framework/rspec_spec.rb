require 'spec_helper'
require 'spork/test_framework_shared_examples'

describe Spork::TestFramework::RSpec do
  it_behaves_like "a TestFramework"

  it "supports rspec 1.x" do
    begin
      Object.const_set(:Spec, Module.new)
      Spec.const_set(:Runner, Module.new)
      Spec::Runner.const_set(:CommandLine, Module.new)
      Spec::Runner.const_set(:OptionParser, Module.new)
      Spec::Runner::OptionParser.stub(:parse)

      framework = Spork::TestFramework::RSpec.new
      framework.stub(:rspec1?).and_return(true)

      Spec::Runner::CommandLine.should_receive(:run)

      framework.run_tests([],StringIO.new,StringIO.new)
    ensure
      Object.__send__(:remove_const, :Spec)
    end
  end

  it "supports rspec >= 2.0" do
    RSpec::Core::CommandLine.any_instance.should_receive(:run)
    framework = Spork::TestFramework::RSpec.new
    framework.run_tests([],StringIO.new,StringIO.new)
  end
end
