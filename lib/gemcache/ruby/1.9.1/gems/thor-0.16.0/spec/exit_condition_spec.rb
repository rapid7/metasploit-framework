require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'thor/base'

describe "Exit conditions" do
  it "should exit 0, not bubble up EPIPE, if EPIPE is raised" do
    epiped = false

    task = Class.new(Thor) do
      desc "my_action", "testing EPIPE"
      define_method :my_action do
        epiped = true
        raise Errno::EPIPE
      end
    end

    lambda { task.start(["my_action"]) }.should raise_error(SystemExit)
    epiped.should == true
  end
end
