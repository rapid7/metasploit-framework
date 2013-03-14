require 'spec_helper'

describe Spork::RunStrategy::Forking do
  before(:each) do
    @fake_framework = FakeFramework.new
    @run_strategy = Spork::RunStrategy::Forking.new(@fake_framework)

  end

  it "returns the result of the run_tests method from the forked child" do
    create_helper_file
    @fake_framework.stub!(:run_tests).and_return("tests were ran")
    @run_strategy.run("test", STDOUT, STDIN).should == "tests were ran"
  end

  it "aborts the current running thread when another run is started" do
    create_helper_file
    @fake_framework.wait_time = 0.25
    first_run = Thread.new { @run_strategy.run("test", STDOUT, STDIN).should == nil }
    sleep(0.05)
    @run_strategy.run("test", STDOUT, STDIN).should == true

    # wait for the first to finish
    first_run.join
  end

  it "can abort the current run" do
    create_helper_file
    @fake_framework.wait_time = 5
    started_at = Time.now
    first_run = Thread.new { @run_strategy.run("test", STDOUT, STDIN).should == true }
    sleep(0.05)
    @run_strategy.send(:abort)
    sleep(0.01) while @run_strategy.running?

    (Time.now - started_at).should < @fake_framework.wait_time
  end
end unless windows?
